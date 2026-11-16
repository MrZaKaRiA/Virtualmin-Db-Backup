# Changelog

All notable changes to the Database Backup Webmin module are documented here.

## [1.1.0] — 2026-11-16

- Add scheduled daily backup folders grouped by project domain, with Virtualmin
  database mappings and optional connection-level domain overrides.
- Write SQLite SQL dumps for daily backups and support SQLite inside Docker.
- Publish complete local daily sets atomically and verify daily cloud copies.
- Browse, download, and verify files inside project folders.

## [1.0.0] — 2026-06-23

Initial release. A hardened, modular successor to the classic
"`mysqldump` everything and `rclone sync`" shell script.

### Added
- Multi-engine backups: MySQL, MariaDB, PostgreSQL, MongoDB, SQLite.
- Two sources per engine: host-installed clients and `docker exec` into running
  containers (auto-detected by image).
- Connection **profiles** holding credentials in root-only files, with a
  read-only "Test" that lists reachable databases.
- **Per-database selection** in the backup form (tick whole connections and/or
  individual databases; default is every database in the connection).
- Timestamped backup **sets** with per-database files, `manifest.json` and
  `SHA256SUMS` integrity files.
- Compression: gzip / zstd / xz / none, with configurable level.
- Optional **at-rest encryption** with GnuPG (AES-256 symmetric).
- **Retention** by set count and/or age, deleting only timestamp-named sets.
- **Cloud upload** via rclone: Amazon S3 (and S3-compatible), Dropbox, Google
  Drive — copy (safe) or sync modes.
- **Browse / verify checksums / download / restore** from the web UI.
- **Scheduled** backups via Webmin's cron module, with a CLI/cron runner
  (`dbbackup-run.pl`).
- Per-user **ACLs**: view, backup, restore, profiles, remotes, schedule, delete.

### Security
- Database secrets, GnuPG passphrases and rclone keys/tokens are never placed on
  a command line (argv) — credentials are passed via `--defaults-extra-file`
  (MySQL), `PGPASSWORD` (PostgreSQL), `--config` (MongoDB), child STDIN for
  Docker dumps, `--passphrase-fd` (GnuPG) and a module-owned `0600` rclone
  config.
- Every shell command is built from literal flags plus `&sq()`-escaped values;
  identifiers are allowlist-validated and may not begin with `-`.
- Retention/deletion is confined to timestamp-named child directories of the
  backup folder (no `rm -rf`, no `find -exec`).
- All state changes are POST-only, individually ACL-gated, and audited with
  `webmin_log` (secrets are never logged).
