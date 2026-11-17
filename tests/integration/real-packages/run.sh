#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.." && pwd)
WASMER_BIN=${WASMER_BIN:-$REPO_ROOT/target/debug/wasmer}

usage() {
  printf 'Usage: %s [all|bash|php|phpix|static|wordpress]\n' "$0"
}

subcommand=${1:-all}
if [[ $subcommand == help || $subcommand == -h || $subcommand == --help ]]; then
  usage
  exit 0
fi

if ! command -v "$WASMER_BIN" >/dev/null 2>&1; then
  printf 'Wasmer executable not found: %s (set WASMER_BIN to override)\n' "$WASMER_BIN" >&2
  exit 127
fi
for tool in curl python3 timeout; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$tool" >&2
    exit 127
  fi
done

RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/run-real-packages.XXXXXX")
chmod 0755 "$RUN_DIR"
LOG_DIR=$RUN_DIR/logs
printf 'Logs and fixtures: %s\n' "$RUN_DIR"
BASH_DATA=$RUN_DIR/bash-data
STATIC_ROOT=$RUN_DIR/static-root
PHP_ROOT=$RUN_DIR/php-root
server_pid=
mysql_container=
mkdir -p "$LOG_DIR" "$BASH_DATA" "$STATIC_ROOT" "$PHP_ROOT"

stop_server() {
  if [[ -n $server_pid ]]; then
    if kill -0 "$server_pid" 2>/dev/null; then
      kill -TERM "$server_pid" 2>/dev/null || true
      for _ in $(seq 1 30); do
        kill -0 "$server_pid" 2>/dev/null || break
        sleep 0.1
      done
      if kill -0 "$server_pid" 2>/dev/null; then
        kill -KILL "$server_pid" 2>/dev/null || true
      fi
    fi
    wait "$server_pid" 2>/dev/null || true
    server_pid=
  fi
}

stop_mysql() {
  if [[ -n $mysql_container ]]; then
    docker logs "$mysql_container" >"$LOG_DIR/mysql.log" 2>&1 || true
    docker rm -fv "$mysql_container" >/dev/null 2>&1 || true
    mysql_container=
  fi
}

cleanup() {
  stop_server
  stop_mysql
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

run_to() {
  printf '\n%s\n' "$1"
  local log_file=$2
  local exit_code=0
  shift 2
  "$@" >"$log_file" 2>&1 || exit_code=$?
  cat "$log_file"
  return "$exit_code"
}

assert_line() {
  expected=$1
  log_file=$2
  if ! grep -Fxq "$expected" "$log_file"; then
    printf 'Expected output line not found: %s (see %s)\n' "$expected" "$log_file" >&2
    return 1
  fi
}

bash_checks() {
  printf 'Write sample.txt: BASH_FILE_OK\n'
  printf 'BASH_FILE_OK\n' > "$BASH_DATA/sample.txt"
  chmod 0644 "$BASH_DATA/sample.txt"

  run_to 'Run Bash: echo hello' "$LOG_DIR/bash-echo.log" timeout --signal=TERM --kill-after=10s 120s \
    "$WASMER_BIN" --quiet run --no-tty wasmer/bash -- -c 'echo hello'
  assert_line hello "$LOG_DIR/bash-echo.log"

  run_to 'Run Bash: cat /data/sample.txt; ls /data' "$LOG_DIR/bash-file.log" timeout --signal=TERM --kill-after=10s 120s \
    "$WASMER_BIN" --quiet run --no-tty --volume "$BASH_DATA:/data" \
    wasmer/bash -- -c 'cat /data/sample.txt; ls /data'
  assert_line BASH_FILE_OK "$LOG_DIR/bash-file.log"
  assert_line sample.txt "$LOG_DIR/bash-file.log"

  # shellcheck disable=SC2016 # Expand the variable in the guest shell.
  run_to 'Run Bash: echo "$PARITY_TEST_ENV" (PARITY_TEST_ENV=ENV-OK)' "$LOG_DIR/bash-env.log" timeout --signal=TERM --kill-after=10s 120s \
    "$WASMER_BIN" --quiet run --no-tty --env PARITY_TEST_ENV=ENV-OK \
    wasmer/bash -- -c 'echo "$PARITY_TEST_ENV"'
  assert_line ENV-OK "$LOG_DIR/bash-env.log"

  run_to 'Run Bash: printf "alpha\nbeta\n" | wc -l' "$LOG_DIR/bash-pipeline.log" timeout --signal=TERM --kill-after=10s 120s \
    "$WASMER_BIN" --quiet run --no-tty wasmer/bash -- -c 'printf "alpha\nbeta\n" | wc -l'
  assert_line 2 "$LOG_DIR/bash-pipeline.log"

  if run_to 'Run Bash: exit 37' "$LOG_DIR/bash-exit.log" timeout --signal=TERM --kill-after=10s 120s \
    "$WASMER_BIN" --quiet run --no-tty wasmer/bash -- -c 'exit 37'; then
    exit_code=0
  else
    exit_code=$?
  fi
  if [[ $exit_code -ne 37 ]]; then
    printf 'Expected Bash guest exit 37, got %s (see %s)\n' "$exit_code" "$LOG_DIR/bash-exit.log" >&2
    return 1
  fi
  printf 'Exit code: %s\n' "$exit_code"
}

choose_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

start_server() {
  printf '\n%s\n' "$1"
  local log_file=$2
  shift 2
  "$@" >"$log_file" 2>&1 &
  server_pid=$!
}

http_get() {
  url=$1
  expected_body=$2
  prefix=$3
  response_file=$prefix.response
  status_file=$prefix.status
  ready=0
  for _ in $(seq 1 40); do
    if curl --noproxy '*' --fail --silent --show-error --connect-timeout 1 --max-time 3 \
      -o "$response_file" -w '%{http_code}' "$url" >"$status_file" 2>"$prefix.curl.log"; then
      ready=1
      break
    fi
    if [[ -n $server_pid ]] && ! kill -0 "$server_pid" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if [[ $ready -ne 1 ]]; then
    printf 'HTTP request failed; see %s and %s\n' "$prefix.curl.log" "$LOG_DIR" >&2
    return 1
  fi
  if [[ $(cat "$status_file") != 200 ]]; then
    printf 'Expected HTTP 200 from %s; got %s\n' "$url" "$(cat "$status_file")" >&2
    return 1
  fi
  assert_line "$expected_body" "$response_file"
}

php_checks() {
  run_to 'Run PHPix: php -v' "$LOG_DIR/phpix-version.log" timeout --signal=TERM --kill-after=10s 120s \
    "$WASMER_BIN" --quiet run --no-tty phpix/phpix-85-32bit -- -v
  if ! grep -qi PHP "$LOG_DIR/phpix-version.log"; then
    printf 'PHPix -v output did not identify PHP; see %s\n' "$LOG_DIR/phpix-version.log" >&2
    return 1
  fi
  run_to "Run PHPix: php -r 'echo \"PHP-RUN-OK\";'" "$LOG_DIR/phpix-run.log" timeout --signal=TERM --kill-after=10s 120s \
    "$WASMER_BIN" --quiet run --no-tty phpix/phpix-85-32bit -- -r 'echo "PHP-RUN-OK";'
  assert_line PHP-RUN-OK "$LOG_DIR/phpix-run.log"

  printf '\nWrite index.php\n'
  cat > "$PHP_ROOT/index.php" <<'PHP'
<?php
header("Content-Type: text/plain");
echo "PHP-HTTP-OK:" . $_GET["q"];
PHP
  chmod 0644 "$PHP_ROOT/index.php"
  port=$(choose_port)
  server_url="http://127.0.0.1:$port/index.php?q=GUEST"
  start_server 'Run PHPix web server (php -S 0.0.0.0:3000 -t /app)' "$LOG_DIR/php-server.log" "$WASMER_BIN" --quiet run --no-tty \
    --volume "$PHP_ROOT:/app" --publish "127.0.0.1:$port:3000" \
    phpix/phpix-85-32bit -- -S 0.0.0.0:3000 -t /app
  http_get "$server_url" PHP-HTTP-OK:GUEST "$LOG_DIR/php-index"
  if [[ $subcommand == all ]]; then
    stop_server
  fi
}

static_checks() {
  printf '\nWrite index.html: STATIC-HTTP-OK\n'
  printf 'STATIC-HTTP-OK\n' > "$STATIC_ROOT/index.html"
  printf 'Write asset.txt: STATIC-ASSET-OK\n'
  printf 'STATIC-ASSET-OK\n' > "$STATIC_ROOT/asset.txt"
  chmod 0644 "$STATIC_ROOT/index.html" "$STATIC_ROOT/asset.txt"
  port=$(choose_port)
  server_url="http://127.0.0.1:$port/"
  start_server 'Run wasmer/static-web-server (serve /www on port 8080)' "$LOG_DIR/static-server.log" "$WASMER_BIN" --quiet run --no-tty \
    --volume "$STATIC_ROOT:/www" --publish "127.0.0.1:$port:8080" \
    wasmer/static-web-server -- -a 0.0.0.0 -p 8080 -d /www
  http_get "$server_url" STATIC-HTTP-OK "$LOG_DIR/static-index"
  http_get "http://127.0.0.1:$port/asset.txt" STATIC-ASSET-OK "$LOG_DIR/static-asset"
  if [[ $subcommand == all ]]; then
    stop_server
  fi
}

wordpress_checks() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'Required command not found: docker\n' >&2
    return 127
  fi

  local package=sha256:24a26c8870a8b8537bad483a1b88b1e1b8bc838e0b5d93ca3852f3840d83607d
  local mysql_port port ready=0
  printf '\nStart MySQL in Docker\n'
  mysql_container=$(docker run --detach --rm --publish 127.0.0.1::3306 \
    --env MYSQL_ROOT_PASSWORD=wordpress-root-test \
    --env MYSQL_DATABASE=wordpress \
    --env MYSQL_USER=wordpress \
    --env MYSQL_PASSWORD=wordpress-test \
    mysql:8.4)
  mysql_port=$(docker inspect --format '{{(index (index .NetworkSettings.Ports "3306/tcp") 0).HostPort}}' "$mysql_container")
  for _ in $(seq 1 120); do
    if docker exec --env MYSQL_PWD=wordpress-test "$mysql_container" \
      mysql --protocol=TCP --host=127.0.0.1 --user=wordpress --database=wordpress \
      --execute='SELECT 1' >"$LOG_DIR/mysql-ready.log" 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done
  if [[ $ready -ne 1 ]]; then
    printf 'MySQL did not become ready; see %s\n' "$LOG_DIR" >&2
    return 1
  fi

  mkdir -p "$RUN_DIR/wordpress-content"
  port=$(choose_port)
  server_url="http://127.0.0.1:$port/"
  # The guest gateway aliases the host loopback where Docker publishes MySQL.
  local wordpress_args=(
    --volume "$RUN_DIR/wordpress-content:/app/wp-content"
    --env DB_HOST=10.0.2.2 --env "DB_PORT=$mysql_port"
    --env DB_NAME=wordpress --env DB_USERNAME=wordpress --env DB_PASSWORD=wordpress-test
    --env "WP_HOME=http://127.0.0.1:$port" --env "WP_SITEURL=http://127.0.0.1:$port"
  )
  run_to 'Install WordPress into MySQL' "$LOG_DIR/wordpress-install.log" timeout --signal=TERM --kill-after=10s 120s \
    "$WASMER_BIN" --quiet run --no-tty "${wordpress_args[@]}" --entrypoint wp "$package" -- \
    core install --url="http://127.0.0.1:$port" --title=WORDPRESS-DB-OK \
    --admin_user=admin --admin_password=wordpress-admin-test --admin_email=admin@example.com --skip-email

  run_to 'Verify WordPress wrote its site title to MySQL' "$LOG_DIR/wordpress-db.log" \
    docker exec --env MYSQL_PWD=wordpress-test "$mysql_container" \
    mysql --protocol=TCP --host=127.0.0.1 --user=wordpress --database=wordpress --batch --skip-column-names \
    --execute="SELECT option_value FROM wp_options WHERE option_name = 'blogname'"
  assert_line WORDPRESS-DB-OK "$LOG_DIR/wordpress-db.log"

  start_server 'Run WordPress web server on port 8080' "$LOG_DIR/wordpress-server.log" \
    "$WASMER_BIN" --quiet run --no-tty "${wordpress_args[@]}" --publish "127.0.0.1:$port:8080" "$package"
  http_get "http://127.0.0.1:$port/wp-login.php" '<!DOCTYPE html>' "$LOG_DIR/wordpress-login"
  if ! grep -Fq 'name="log"' "$LOG_DIR/wordpress-login.response"; then
    printf 'WordPress login form not found; see %s\n' "$LOG_DIR/wordpress-login.response" >&2
    return 1
  fi
  if [[ $subcommand == all ]]; then
    stop_server
    stop_mysql
  fi
}

case "$subcommand" in
  all)
    bash_checks
    php_checks
    static_checks
    wordpress_checks
    ;;
  bash)
    bash_checks
    ;;
  php|phpix)
    php_checks
    ;;
  static)
    static_checks
    ;;
  wordpress)
    wordpress_checks
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [[ -n $server_pid ]]; then
  printf '\nOpen %s\nPress Ctrl+C to stop.\n' "$server_url"
  wait "$server_pid"
fi
