# Journaling retirement

Journaling, snapshot/restore, and compatibility with old journal formats are
intentionally excluded from this delivery at the user's request. The CLI journal
commands, run options, Cargo feature, and provider dependency have been removed.
This removal is intentional and is not a pending compatibility requirement.

The old `wasmer-journal` implementation remains temporarily because the legacy
runtime still imports it. It will be removed with that runtime; no replacement
journal-format owner, adapter, or migration of old journals is planned. See the
[consumer retirement map](./WASIX-MIGRATION.md).
