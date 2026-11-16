<div align="center">

# 🛡️ Virtualmin Database Backup

### A hardened, point-and-click Webmin & Virtualmin module for backing up every database on your server

MySQL · MariaDB · PostgreSQL · MongoDB · SQLite — **on the host or inside Docker containers** —
with compression, integrity checksums, encryption, retention, **cloud upload** (S3 · Dropbox · Google Drive)
and **scheduled jobs**. It **detects what's already on your system** so you click instead of type.

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)
[![Webmin module](https://img.shields.io/badge/Webmin-module-FF6600.svg)](https://webmin.com)
[![Virtualmin](https://img.shields.io/badge/Virtualmin-friendly-2E7D32.svg)](https://virtualmin.com)
[![Version](https://img.shields.io/badge/version-1.1.0-success.svg)](CHANGELOG.md)
[![Hardened](https://img.shields.io/badge/secrets-never--on--argv-brightgreen.svg)](#-security-model)

</div>

---

> **Why another backup tool?** Because the usual answer — a `mysqldump` one-liner with the
> password in the script and a `find … -exec rm -rf` for cleanup — runs **as root**, leaks
> credentials into `ps`, silently ships gzipped error messages when a dump fails, and can wipe
> the wrong directory. This module fixes all of that and gives you a UI on top: it builds every
> command from constant flags plus individually escaped values, **never puts a secret on a
> command line**, verifies each dump, and only ever deletes its own timestamped backup sets.

Live under **Webmin / Virtualmin**? This fits right in — under **Servers → Database Backup**.

## ✨ Highlights

- 🔒 **Secrets never touch argv** — credentials go via option files, env vars, `--config`, or the child's STDIN, never where `ps` can see them.
- 🧲 **Grabs what's already there** — imports connections from Webmin's own MySQL/PostgreSQL modules, reads the root password straight out of Docker containers, and picks up your existing `rclone` remotes.
- 🗄️ **Five engines, host *and* Docker** — MySQL, MariaDB, PostgreSQL, MongoDB, SQLite; host installs and running containers are auto-detected.
- ☁️ **Cloud built in** — upload to Amazon S3 (and S3-compatible), Dropbox, or Google Drive via `rclone`, with safe **copy** or mirroring **sync**.
- 🔐 **Safe by construction** — integrity SHA-256 sums, optional GnuPG encryption at rest, and retention that can only delete its own backup sets — no `rm -rf`, no `find -exec`.
- ⏰ **Scheduled** — cron jobs created through Webmin, with a CLI/cron runner for unattended backups.
- 👥 **Granular ACLs & audited** — per-user permissions, every change POST-only and written to the Webmin Actions Log (never logging a secret).

## 📸 Screenshots

> Drop your own PNGs into `docs/screenshots/` — they'll render here.

| Dashboard | Connections (detected) | Back up & schedule |
| --- | --- | --- |
| ![Dashboard](docs/screenshots/dashboard.png) | ![Connections](docs/screenshots/connections.png) | ![Backup](docs/screenshots/backup.png) |

## 🚀 Features

<table>
<tr><td valign="top" width="50%">

**Connections — detected, not typed**
- One-click **Import** from Webmin's MySQL/PostgreSQL modules
- Docker containers auto-detected; admin password read from the container's environment
- Container **dropdown**, SQLite **file browser**, destination **directory browser**
- Auto-named from the database's domain/path (great for Virtualmin shared hosting)

**Engines & sources**
- MySQL · MariaDB · PostgreSQL · MongoDB · SQLite
- Host-installed clients **or** `docker exec` into a running container
- Per-database selection, or "all databases" per connection

**Backups**
- Timestamped sets, one file per database
- `manifest.json` + `SHA256SUMS` for every set
- Compression: gzip · zstd · xz · none
- Optional **GnuPG AES-256** encryption at rest

</td><td valign="top" width="50%">

**Retention**
- Keep at most *N* sets and/or delete sets older than *D* days
- Deletes **only** timestamp-named sets it created — symlink-safe

**Cloud upload (rclone)**
- Amazon S3 & S3-compatible (MinIO, Wasabi, Ceph, DO Spaces…)
- Dropbox · Google Drive (paste an OAuth token)
- **Import** remotes already in the server's `rclone.conf`
- Safe **copy** or mirroring **sync** modes

**Browse · verify · restore**
- List sets, verify checksums, download, delete
- Restore into MySQL/MariaDB/PostgreSQL/MongoDB/SQLite

**Scheduling**
- Cron jobs via Webmin; non-zero exit on failure so cron emails you
- Run-now button + standalone `dbbackup-run.pl`

**Access control**
- Per-user: view · backup · restore · profiles · remotes · schedule · delete

</td></tr>
</table>

## 🔁 Replaces the classic backup script

| The old way | The problem | This module |
| --- | --- | --- |
| `PASSWORD="…"` in the file; `mysqldump -p$PASSWORD` | Secret in plaintext **and** in `ps` | Off-argv via `--defaults-extra-file`, `PGPASSWORD`, `--config`, or container STDIN |
| `mysqldump \| gzip > out.gz` | A failed dump still "succeeds" | Dump → **verify exit + non-empty** → compress → checksum |
| `find $OUT -mtime +30 -exec rm -rf {} \;` | Can wipe the wrong directory | Deletes **only** timestamp-named sets, never follows symlinks |
| `rclone sync` to one fixed remote | `sync` can delete remote data | Per-job **copy** (default) or **sync**, across S3 / Dropbox / Drive |
| MySQL only, host only | Misses Docker DBs & other engines | 5 engines, host **and** containers, auto-detected |

## 🔒 Security model

This is the whole point of the module.

| Guarantee | How |
| --- | --- |
| **No secret on a command line** | MySQL via a `0600` `--defaults-extra-file`; PostgreSQL via `PGPASSWORD`; MongoDB via a `--config` file; **Docker** dumps stream the password on the child's STDIN into an in-container env var / temp config; GnuPG via `--passphrase-fd`; rclone keys/tokens written to a `0600` config we own — never on argv. |
| **No shell injection** | Every value from a form, profile, schedule or Docker output is single-quote-escaped (`sq()`); only constant flags stay literal. |
| **Allowlist validation** | Identifiers (DB names, profile ids, container refs, remotes) are checked against anchored regexes and may never begin with `-` (no option injection). |
| **Destruction stays in its lane** | Retention/delete only ever touches timestamp-named child directories of the backup folder; `lstat` rejects symlinks; no `rm -rf`, no `find -exec`. |
| **POST-only, ACL-gated, audited** | All changes go through one dispatcher (`act.cgi`), reached only by POST, permission-checked, and logged with `webmin_log` — secrets are never logged or reflected into a page. |
| **Integrity** | SHA-256 for every file; optional GnuPG AES-256 encryption at rest. |

Each finding from a multi-pass adversarial review (shell injection, secret leakage, path/retention
safety, Perl correctness, Webmin API use, authorization, engine semantics) was verified and fixed
before release.

## 📦 Requirements

- A host running **Webmin** (or **Virtualmin**)
- The client tools for what you back up: `mysqldump`/`mariadb-dump`, `pg_dump`/`psql`,
  `mongodump`/`mongorestore`, `sqlite3` — on the host or in the container
- `gzip` (and optionally `zstd` / `xz`); `gpg` for encryption
- `rclone` for cloud upload (optional); `docker` for container databases (optional)
- Perl `JSON::PP` (ships with Perl 5.14+)

## ⚙️ Installation

1. Download **`dbbackup.wbm.gz`** from the [latest release](../../releases/latest).
2. In Webmin go to **Webmin Configuration → Webmin Modules → From uploaded file**,
   choose the package, and click **Install Module**.
3. Open it under **Servers → Database Backup**.

Build it yourself from a checkout:

```sh
tar -czf dbbackup.wbm.gz dbbackup     # the top-level dir in the archive must be "dbbackup"
```

## 🧭 Quick start

1. **Connections → Detected sources → Import** next to your MySQL/Docker database — credentials
   are pulled in automatically. (SQLite: **Add**, then **Browse** to the file; leave the name
   blank and it's auto-named from the domain.)
2. **Test** the connection to list its databases.
3. **Back up now** — pick databases, choose the destination (Browse), compression, retention,
   encryption, and a cloud remote.
4. **Cloud remotes → Detected remotes → Import** to reuse an existing `rclone` setup.
5. **Schedules** — add a cron job to run it unattended.

## 🗂️ How backups are laid out

```
<backup dir>/
  2026-06-23_021500_nightly/        # timestamp[_label]
    arabicama_database.sqlite.gz    # SQLite, labelled by domain
    shop_wordpress.sql.gz           # MySQL
    app_all.archive.gz              # MongoDB
    SHA256SUMS
    manifest.json
```

### Daily folders by project domain

In **Schedules**, choose **Daily folders by project domain** under **Backup layout**,
select the connection profiles, and use a dedicated destination such as
`/home/DatabaseBackup`. Set **Base folder/path on the remote** in the module settings
to mirror the root folder name on Dropbox.

```text
DatabaseBackup/
  2026-11-16/
    app.example.test/
      app.sql.gz
    shop.example.test/
      orders.sql.gz
    SHA256SUMS
    manifest.json
```

Virtualmin's local database assignments and site home directories supply the
domain names. Set **Project domain or subdomain** on Docker profiles and other
connections that need an explicit mapping. Databases with no match go into
`unassigned`. Add SQLite files to a connection profile. For SQLite inside Docker,
specify the paths inside the running container and make sure it has `sqlite3`.
Daily SQLite backups are SQL dumps.

Use one daily schedule per destination. The server's local date determines the
folder name. A rerun of the same schedule reuses that day's completed local set
and retries the cloud copy. Daily uploads use rclone copy and verification.
Local retention applies to completed daily sets.

## ☁️ Cloud remotes

- **Amazon S3 / S3-compatible** — fully non-interactive: access key, secret, region (endpoint for
  non-AWS).
- **Dropbox / Google Drive** — run `rclone authorize "dropbox"` (or `"drive"`) on any machine with
  a browser and paste the JSON token.
- **Import** — any remote already in root's `~/.config/rclone/rclone.conf` is offered for one-click
  import (keys/tokens come along).

Keys and tokens are written only to the module's own `0600` config — never passed to `rclone` on
the command line.

## 👥 Access control

Under **Webmin Users → _user_ → Database Backup**, grant or deny each capability independently:
**view · backup · restore · profiles · remotes · schedule · delete**. Default is full access
(you're the admin); tighten per user as needed.

## 🗂️ Module layout

| File | Purpose |
| --- | --- |
| `dbbackup-lib.pl` | Hardened core: shell quoting, validation, every dump/restore, compression, encryption, checksums, retention, rclone, cron, detection |
| `index.cgi` | Dashboard: status, detected databases, quick backup |
| `profiles.cgi` | Connections — detection/import, container dropdown, SQLite browser |
| `backup.cgi` | Choose databases / path / compression / retention / cloud and run |
| `remotes.cgi` | Cloud remotes: S3 / Dropbox / Drive + import from system rclone |
| `browse.cgi` · `restore.cgi` | Browse / verify / download / delete · restore |
| `schedule.cgi` · `dbbackup-run.pl` | Cron scheduling · unattended runner |
| `act.cgi` | The single POST action dispatcher (ACL-gated, audited) |
| `acl_security.pl` · `defaultacl` · `install_check.pl` | Per-user access control · auto-detection |

## 🤝 Contributing

Issues and pull requests welcome. Every `.cgi`/`.pl` file is validated with `perl -c` in CI;
changes to command construction must keep the `sq()` + allowlist + secrets-off-argv discipline.

## 📜 License

Copyright © 2026 MrZaKaRiA.

This program is free software; you can redistribute it and/or modify it under the terms of the
[GNU General Public License version 2](LICENSE) as published by the Free Software Foundation. It is
distributed **without any warranty** — see the license for details.

---

<div align="center">
<sub>Built for the Webmin & Virtualmin community.</sub>
</div>
