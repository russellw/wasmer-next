//! Source-built WASIX v1 guest conformance tests.

#![cfg(unix)]
#![recursion_limit = "256"]

use anyhow::{Context, Result, anyhow, bail, ensure};
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use wasixv2::{
    ByteSink, ByteSource, Compile, Credentials, Image, LoadError, Loader, LocalFuture, Machine,
    ProcessConfig, Stdio,
};
use wasmer::{Engine, Module};

#[derive(Debug, Clone, PartialEq, Eq)]
struct MappedDirectory {
    host: String,
    guest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    source: String,
    test_src_dir: PathBuf,
    config_name: String,
    is_abstract: bool,
    arguments: Vec<String>,
    build_env: Vec<(String, String)>,
    env: Vec<String>,
    nonzero_exit_code: bool,
    expected_exit_code: i32,
    expected_stdout: Vec<String>,
    expected_stderr: Vec<String>,
    stdin: Option<Vec<u8>>,
    mapped_directories: Vec<MappedDirectory>,
    current_directory: Option<String>,
    prefilled_files: Vec<(PathBuf, String)>,
    expected_files: Vec<(PathBuf, String)>,
    program_name: Option<String>,
    default_mapped_directories: bool,
}

impl Config {
    fn new(source: String, test_src_dir: PathBuf) -> Self {
        Self {
            source,
            test_src_dir,
            config_name: "default".to_owned(),
            is_abstract: false,
            arguments: Vec::new(),
            build_env: Vec::new(),
            env: Vec::new(),
            nonzero_exit_code: false,
            expected_exit_code: 0,
            expected_stdout: Vec::new(),
            expected_stderr: Vec::new(),
            stdin: None,
            mapped_directories: Vec::new(),
            current_directory: None,
            prefilled_files: Vec::new(),
            expected_files: Vec::new(),
            program_name: None,
            default_mapped_directories: true,
        }
    }
}

fn parse_configs(default_config: &Config) -> Result<Vec<Config>> {
    let src_filename = default_config.test_src_dir.join(&default_config.source);
    let source = std::fs::read_to_string(&src_filename)
        .with_context(|| format!("Failed to read {}", src_filename.display()))?;

    let mut configs = Vec::new();
    let mut config_name_to_index = HashMap::new();
    let mut config = default_config.clone();
    let mut build_env = Vec::new();

    for (i, line) in source.lines().enumerate() {
        if let Some(rest) = line
            .trim()
            .strip_prefix(if default_config.source.ends_with(".sh") {
                "##"
            } else {
                "//#"
            })
        {
            process_directive(
                rest,
                &mut build_env,
                &mut config,
                default_config,
                &mut config_name_to_index,
                &mut configs,
            )
            .with_context(|| {
                format!(
                    "Failed to process test directive {}:{}",
                    src_filename.display(),
                    i + 1
                )
            })?;
        }
    }

    configs.push(config);

    for config in &mut configs {
        config.build_env = build_env.clone();
    }

    configs.retain(|c| !c.is_abstract);

    if configs.is_empty() {
        bail!("Missing non-abstract Config");
    }

    Ok(configs)
}

fn process_directive(
    rest: &str,
    build_env: &mut Vec<(String, String)>,
    config: &mut Config,
    default_config: &Config,
    config_name_to_index: &mut HashMap<String, usize>,
    configs: &mut Vec<Config>,
) -> Result<()> {
    let (directive, arg) = rest.split_once(':').context("Missing arg")?;
    let arg = arg.trim();
    match directive {
        "Config" | "AbstractConfig" => {
            if config != default_config {
                let index = configs.len();
                config_name_to_index.insert(config.config_name.clone(), index);
                configs.push(config.clone());
            }

            let name = if let Some((name, inherit)) = arg.split_once(':') {
                let inherit_index = config_name_to_index.get(inherit).ok_or_else(|| {
                    anyhow!("Config `{name}` inherits from unknown config named `{inherit}`")
                })?;

                *config = configs[*inherit_index].clone();
                name
            } else {
                *config = default_config.clone();
                arg
            };
            config.is_abstract = directive == "AbstractConfig";
            if config_name_to_index.contains_key(name) {
                bail!("Duplicate config `{name}`");
            }
            name.clone_into(&mut config.config_name);
        }
        "AbstractConfigFile" => {
            let path = config
                .test_src_dir
                .join(parse_relative_path(arg, "AbstractConfigFile")?);
            process_directive_file(
                &path,
                build_env,
                config,
                default_config,
                config_name_to_index,
                configs,
            )?;
        }
        "Args" => {
            config.arguments = arg
                .split(' ')
                .map(str::to_owned)
                .filter(|s| !s.is_empty())
                .collect();
        }
        "ExpectedStdout" => {
            config.expected_stdout.push(arg.to_owned());
        }
        "ExpectedStderr" => {
            config.expected_stderr.push(arg.to_owned());
        }
        "ExpectedStdoutFile" => {
            config.expected_stdout.extend(read_expected_lines(
                &config.test_src_dir,
                arg,
                "ExpectedStdoutFile",
            )?);
        }
        "ExpectedStderrFile" => {
            config.expected_stderr.extend(read_expected_lines(
                &config.test_src_dir,
                arg,
                "ExpectedStderrFile",
            )?);
        }
        "BuildEnv" => {
            let (key, value) = arg
                .split_once('=')
                .ok_or_else(|| anyhow!("missing equals separator for BuildEnv"))?;
            let key = key.trim();
            ensure!(!key.is_empty(), "BuildEnv key must not be empty");
            build_env.push((key.to_owned(), value.trim().to_owned()));
        }
        "Env" => {
            let (key, value) = arg
                .split_once('=')
                .ok_or_else(|| anyhow!("missing equals separator for Env"))?;
            let key = key.trim();
            ensure!(!key.is_empty(), "Env key must not be empty");
            config.env.push(format!("{key}={}", value.trim()));
        }
        "MustFail" => {
            config.nonzero_exit_code = arg.parse::<bool>()?;
        }
        "ExpectedExitCode" => {
            config.expected_exit_code = arg.parse::<i32>()?;
        }
        "Ignored" | "SkipEngine" | "UnixOnly" | "IgnoreMacOS" | "MinimalLibc" => {
            // Legacy runner restrictions. Adapter exclusions are tracked explicitly.
        }
        "MappedDirectory" => {
            let (host, guest) = arg
                .split_once(':')
                .ok_or_else(|| anyhow!("missing colon separator for MappedDirectory"))?;
            config.mapped_directories.push(MappedDirectory {
                host: host.to_owned(),
                guest: guest.to_owned(),
            });
        }
        "CurrentDirectory" => {
            config.current_directory = Some(arg.to_owned());
        }
        "PrefilledFile" => {
            let (path, file_content) = arg
                .split_once(':')
                .ok_or_else(|| anyhow!("missing colon separator for PrefilledFile"))?;
            let path = PathBuf::from(path);
            ensure!(
                path.is_relative(),
                "PrefilledFile must be relative: {path:?}"
            );
            config.prefilled_files.push((path, file_content.to_owned()));
        }
        "ExpectedFile" => {
            let (path, file_content) = arg
                .split_once(':')
                .ok_or_else(|| anyhow!("missing colon separator for ExpectedFile"))?;
            let path = PathBuf::from(path);
            ensure!(
                path.is_relative(),
                "ExpectedFile must be relative: {path:?}"
            );
            config.expected_files.push((path, file_content.to_owned()));
        }
        "Stdin" => {
            config.stdin = Some(arg.as_bytes().to_vec());
        }
        "StdinFile" => {
            config.stdin = Some(read_fixture_bytes(&config.test_src_dir, arg, "StdinFile")?);
        }
        "ProgramName" => {
            config.program_name = Some(arg.to_owned());
        }
        "DefaultMappedDirectories" => {
            config.default_mapped_directories = arg.parse::<bool>()?;
        }
        other => bail!("Unknown directive '{other}'"),
    }
    Ok(())
}

fn process_directive_file(
    path: &Path,
    build_env: &mut Vec<(String, String)>,
    config: &mut Config,
    default_config: &Config,
    config_name_to_index: &mut HashMap<String, usize>,
    configs: &mut Vec<Config>,
) -> Result<()> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        process_directive(
            line,
            build_env,
            config,
            default_config,
            config_name_to_index,
            configs,
        )
        .with_context(|| {
            format!(
                "Failed to process test directive {}:{}",
                path.display(),
                i + 1
            )
        })?;
    }
    Ok(())
}

fn parse_relative_path(arg: &str, directive: &str) -> Result<PathBuf> {
    let path = PathBuf::from(arg);
    ensure!(path.is_relative(), "{directive} must be relative: {path:?}");
    Ok(path)
}

fn read_expected_lines(test_src_dir: &Path, arg: &str, directive: &str) -> Result<Vec<String>> {
    let path = parse_relative_path(arg, directive)?;
    let contents = std::fs::read_to_string(test_src_dir.join(&path))
        .with_context(|| format!("failed to read {directive} {}", path.display()))?;
    Ok(contents.trim().lines().map(str::to_owned).collect())
}

fn read_fixture_bytes(test_src_dir: &Path, arg: &str, directive: &str) -> Result<Vec<u8>> {
    let path = parse_relative_path(arg, directive)?;
    std::fs::read(test_src_dir.join(&path))
        .with_context(|| format!("failed to read {directive} {}", path.display()))
}

fn collect_cases(root: &Path) -> Result<BTreeMap<String, Config>> {
    let mut cases = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry?;
        if !entry.file_type().is_dir() || entry.path() == root {
            continue;
        }
        let dir = entry.path();
        let mut scripts = Vec::new();
        for file in fs::read_dir(dir)? {
            let file = file?;
            if file.path().extension().is_some_and(|ext| ext == "sh") {
                scripts.push(file.file_name().into_string().expect("UTF-8 fixture name"));
            }
        }
        let sources = if !scripts.is_empty() {
            scripts
        } else {
            ["main.c", "main.cpp"]
                .into_iter()
                .filter(|file| dir.join(file).is_file())
                .map(str::to_owned)
                .collect()
        };
        for source in sources {
            let path = dir.strip_prefix(root)?.display();
            let fixture = match source.as_str() {
                "build.sh" | "main.c" | "main.cpp" => path.to_string(),
                _ => format!("{path}/{}", source.trim_end_matches(".sh")),
            };
            for config in parse_configs(&Config::new(source, dir.to_owned()))? {
                let name = format!("{fixture}/{}", config.config_name);
                ensure!(
                    cases.insert(name.clone(), config).is_none(),
                    "duplicate case {name}"
                );
            }
        }
    }
    Ok(cases)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry?;
        let target = destination.join(entry.path().strip_prefix(source)?);
        if entry.file_type().is_dir() {
            fs::create_dir_all(target)?;
        } else if entry.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(entry.path())?, target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn build(config: &Config, cc: &Path, dir: &Path) -> Result<Vec<u8>> {
    let cxx = cc.with_file_name("wasix++");
    let mut cmd = match config.source.as_str() {
        "main.c" => Command::new(cc),
        "main.cpp" => Command::new(&cxx),
        _ => Command::new("bash"),
    };
    cmd.arg(&config.source);
    if matches!(config.source.as_str(), "main.c" | "main.cpp") {
        cmd.args(["-o", "main"]);
    }
    let output = cmd
        .current_dir(dir)
        .env("CC", cc)
        .env("CXX", cxx)
        .env("WASIXCC_DISCARD_UNSUPPORTED_FLAGS", "yes")
        .env("WASMER_BACKEND", "cranelift")
        .env("WASMER_ARCH", std::env::consts::ARCH)
        .envs(config.build_env.iter().cloned())
        .output()?;
    ensure!(
        output.status.success(),
        "build failed ({})\n{}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(fs::read(dir.join("main"))?)
}

#[derive(Default)]
struct Capture(Mutex<Vec<u8>>);

impl ByteSink for Capture {
    fn write<'a>(&'a self, data: &'a [u8]) -> LocalFuture<'a, io::Result<usize>> {
        self.0.lock().unwrap().extend_from_slice(data);
        Box::pin(async move { Ok(data.len()) })
    }
}

struct Input(Mutex<io::Cursor<Vec<u8>>>);

impl ByteSource for Input {
    fn poll_read(&self, _: &mut TaskContext<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(self.0.lock().unwrap().read(buf))
    }
}

/// Compiles each distinct image once, as the legacy runner's module cache did.
#[derive(Default)]
struct Cached(Mutex<HashMap<Vec<u8>, (Engine, Module)>>);

impl Loader for Cached {
    fn load<'a>(
        &'a self,
        engine: &'a Engine,
        image: &'a Image,
    ) -> LocalFuture<'a, Result<(Engine, Module), LoadError>> {
        Box::pin(async move {
            if let Some(loaded) = self.0.lock().unwrap().get(image.bytes()) {
                return Ok(loaded.clone());
            }
            let loaded = Compile.load(engine, image).await?;
            let mut modules = self.0.lock().unwrap();
            modules.insert(image.bytes().to_vec(), loaded.clone());
            Ok(loaded)
        })
    }

    fn load_side_module<'a>(
        &'a self,
        host: &'a dyn wasixv2::Host,
        engine: &'a Engine,
        key: wasmer_types::ModuleHash,
        wasm: Vec<u8>,
    ) -> LocalFuture<'a, Result<Module, LoadError>> {
        Compile.load_side_module(host, engine, key, wasm)
    }
}

fn run(config: &Config, wasm: &[u8], dir: &Path) -> Result<Result<()>> {
    for (path, contents) in &config.prefilled_files {
        fs::write(dir.join(path), contents)?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    tokio::task::LocalSet::new().block_on(&runtime, async {
        // Legacy guests ran without permission checks: root is the closest identity.
        let mut machine = Machine::builder()
            .user(Credentials::new(0, 0))
            .loader(Arc::new(Cached::default()))
            .build();
        if config.default_mapped_directories {
            for guest in ["/fixture", "/lib", "/data"] {
                machine.mount_host_dir(guest, dir, false).await?;
            }
            machine.set_working_dir("/fixture");
        }
        let mut temporary_mounts = Vec::new();
        for mapping in &config.mapped_directories {
            let host = if mapping.host == "$temp" {
                temporary_mounts.push(tempfile::tempdir()?);
                temporary_mounts.last().unwrap().path().to_owned()
            } else {
                dir.join(&mapping.host)
            };
            machine.mount_host_dir(&mapping.guest, &host, false).await?;
        }
        if let Some(cwd) = &config.current_directory {
            machine.set_working_dir(cwd);
        }
        let stdout = Arc::new(Capture::default());
        let stderr = Arc::new(Capture::default());
        let process = ProcessConfig {
            args: std::iter::once(config.program_name.clone().unwrap_or_else(|| "main".into()))
                .chain(config.arguments.iter().cloned())
                .collect(),
            env: config.env.clone(),
            stdio: Stdio {
                stdin: Arc::new(Input(Mutex::new(io::Cursor::new(
                    config.stdin.clone().unwrap_or_default(),
                )))),
                stdout: stdout.clone(),
                stderr: stderr.clone(),
            },
        };
        let engine = Engine::default();
        let guest = async {
            if config.default_mapped_directories {
                machine.run_file(&engine, "/fixture/main", process).await
            } else {
                machine.run_process(wasm, process).await
            }
        };
        let status = tokio::time::timeout(Duration::from_secs(15), guest).await;
        let stdout = stdout.0.lock().unwrap();
        let stdout = String::from_utf8_lossy(&stdout);
        let stderr = stderr.0.lock().unwrap();
        let stderr = String::from_utf8_lossy(&stderr);
        Ok(check_output(
            config,
            status
                .map_err(|_| anyhow!("guest timed out"))
                .and_then(|s| s.map_err(anyhow::Error::from)),
            &stdout,
            &stderr,
            dir,
        )
        .with_context(|| format!("stdout: {stdout:?}\nstderr: {stderr:?}")))
    })
}

fn check_output(
    config: &Config,
    status: Result<i32>,
    stdout: &str,
    stderr: &str,
    dir: &Path,
) -> Result<()> {
    let status = status?;
    if config.nonzero_exit_code {
        ensure!(status != 0, "expected nonzero exit status, got {status}");
    } else {
        ensure!(
            status == config.expected_exit_code,
            "expected exit {}, got {status}",
            config.expected_exit_code
        );
    }
    for (stream, actual, expected) in [
        ("stdout", stdout, &config.expected_stdout),
        ("stderr", stderr, &config.expected_stderr),
    ] {
        let lines = actual.trim().lines().collect::<Vec<_>>();
        ensure!(
            expected.is_empty() || lines == *expected,
            "unexpected {stream}: expected {expected:?}, got {lines:?}"
        );
    }
    for (path, expected) in &config.expected_files {
        let actual = fs::read_to_string(dir.join(path))
            .with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            actual == *expected,
            "unexpected contents of {}",
            path.display()
        );
    }
    Ok(())
}

fn read_list(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut entries = BTreeMap::new();
    for line in fs::read_to_string(path)?.lines().map(str::trim) {
        if !line.is_empty() && !line.starts_with('#') {
            let (name, reason) = line
                .split_once(" # ")
                .context("expected a case name and reason")?;
            ensure!(!reason.trim().is_empty(), "missing reason for {name}");
            ensure!(
                entries.insert(name.to_owned(), reason.to_owned()).is_none(),
                "duplicate case {name}"
            );
        }
    }
    Ok(entries)
}

fn compiler() -> Result<Option<PathBuf>> {
    let configured = std::env::var_os("WASIX1_TEST_CC");
    let cc = PathBuf::from(configured.as_deref().unwrap_or("wasixcc".as_ref()));
    let resolved = if cc.components().count() > 1 {
        cc.is_file().then_some(cc)
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|dir| dir.join(&cc))
            .find(|path| path.is_file())
    };
    ensure!(
        configured.is_none() || resolved.is_some(),
        "WASIX1_TEST_CC does not name a compiler"
    );
    Ok(resolved.map(std::path::absolute).transpose()?)
}

#[test]
fn legacy_c_suite() -> Result<()> {
    let Some(cc) = compiler()? else {
        eprintln!("skipped: install a WASIX v1 compiler or set WASIX1_TEST_CC");
        return Ok(());
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wasm_tests");
    let cases = collect_cases(&root)?;
    let expected_path = root.join("expected-failures.txt");
    let mut expected = read_list(&expected_path)?;
    let excluded = read_list(&root.join("excluded.txt"))?;
    for name in expected.keys().chain(excluded.keys()) {
        ensure!(cases.contains_key(name), "unknown case {name}");
        ensure!(
            !(expected.contains_key(name) && excluded.contains_key(name)),
            "excluded case {name} is listed as an expected failure"
        );
    }
    let filter = std::env::var("WASIX1_TESTS_FILTER").unwrap_or_default();
    let bless = std::env::var("WASIX1_TESTS_BLESS").as_deref() == Ok("1");
    let (mut passed, mut failed, mut skipped) = (0, 0, 0);
    let mut unexpected = Vec::new();
    for (name, config) in cases.iter().filter(|(name, _)| name.contains(&filter)) {
        if excluded.contains_key(name) {
            skipped += 1;
            continue;
        }
        let temporary = tempfile::tempdir()?;
        let source = config.test_src_dir.strip_prefix(&root)?;
        let group = source.components().next().unwrap().as_os_str();
        copy_tree(&root.join(group), &temporary.path().join(group))?;
        let dir = temporary.path().join(source);
        let wasm = match build(config, &cc, &dir) {
            Ok(wasm) => wasm,
            Err(error) => {
                eprintln!("BUILD ERROR {name}: {error:#}");
                unexpected.push(name.clone());
                continue;
            }
        };
        let result = run(config, &wasm, &dir).with_context(|| format!("setting up {name}"))?;
        match result {
            Ok(()) => {
                passed += 1;
                println!("PASS {name}");
                if expected.contains_key(name) && !bless {
                    unexpected.push(format!("{name} unexpectedly passed"));
                }
                expected.remove(name);
            }
            Err(error) => {
                failed += 1;
                println!("FAIL {name}: {error:#}");
                if bless {
                    let reason = error.root_cause().to_string();
                    expected
                        .entry(name.clone())
                        .or_insert_with(|| reason.lines().next().unwrap().to_owned());
                } else if !expected.contains_key(name) {
                    unexpected.push(format!("{name}: {error:#}"));
                }
            }
        }
    }
    println!("WASIX v1 C suite: {passed} passed, {failed} failed, {skipped} excluded");
    ensure!(
        passed + failed > 0 || !unexpected.is_empty(),
        "no runnable cases matched {filter:?}"
    );
    ensure!(
        unexpected.is_empty(),
        "unexpected results:\n{}",
        unexpected.join("\n")
    );
    if bless {
        let mut list = String::from("# case # reason\n");
        for (name, reason) in expected {
            list.push_str(&format!("{name} # {reason}\n"));
        }
        fs::write(expected_path, list)?;
    }
    Ok(())
}
