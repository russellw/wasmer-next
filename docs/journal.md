# Journaling retirement

Journaling, snapshot/restore and old journal-format compatibility remain
intentionally excluded. The old journal crate and its legacy runtime consumer
are deleted. No journal adapter or old-format migration is planned.
The v2 adapter's proc_snapshot remains unsupported; see lib/wasix/TODO.md.
