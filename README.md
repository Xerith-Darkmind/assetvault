# AssetVault

AssetVault is an encrypted, local-first inventory for IT assets, backup status, and insurance documentation. It keeps everything in an encrypted SQLite file on your own machine and comes with a dashboard that only listens on localhost.

It's built as the storage and UI layer for a Grok Bot, but it also runs on its own.

## What it does today

- Encrypted item inventory: rooms, categories, serials, values, warranty, owner, OS, MAC address, and encryption status.
- Encrypted photo and receipt attachments, stored as separate encrypted blobs.
- Backup tracking: backup history per item, an RPO target in hours, Met / At risk / Breached status, and a 30-day strip showing each day's result.
- Completeness flags (missing serial, value, receipt, photo, or room) and warranty expiry status.
- An encrypted audit log of setup, migrations, dashboard start and stop, and serial reveals.
- A localhost dashboard for viewing, adding, editing, and deleting items, logging backups, and attaching files.

### Planned (not implemented in this code yet)

- CSV import and the duplicate merge review. The dashboard shows a placeholder.
- Read-only connectors for Entra ID/Intune, Active Directory, and Jamf. The schema already has columns and tables for them, but there is no sync code.
- CSV and PDF export. The dashboard buttons only show a notice.

## Security model

- **Encrypted at rest.** The database, attachments, and audit log are encrypted with AES-256-GCM. The key comes from your passphrase through Argon2id (t=3, m=64 MiB, p=4), or through scrypt if `argon2-cffi` isn't installed. Decrypted data exists only in process memory.
- **The passphrase is never stored.** It's read from `ASSETVAULT_PASSPHRASE` when the program starts. `vault.meta.json` holds only the KDF parameters, the salt, and an encrypted key-check value.
- **The dashboard is bound to 127.0.0.1.** It also needs a random per-session URL token, rejects any Host header other than localhost, rejects cross-origin POSTs, and shuts down after 30 minutes idle (`ASSETVAULT_IDLE_SECONDS`). `bin/lock.sh` stops it.
- **No telemetry.** The code makes no outbound network calls, and the dashboard loads nothing from external sources.
- **Plaintext on disk:** `vault.meta.json`, which is the KDF metadata above; `audit.failed_unlocks`, which holds only timestamps; and `.dashboard_url` / `.dashboard.pid` while the dashboard is running (mode 0600, with the URL containing the session token).

## Install

Requires Python 3.11+ and `git` (git is only needed for the piped install).

```bash
curl -fsSL https://raw.githubusercontent.com/Xerith-Darkmind/assetvault/main/install.sh | bash
```

or

```bash
git clone https://github.com/Xerith-Darkmind/assetvault.git
cd assetvault && ./install.sh
```

The installer copies `bin/` and `ui/` into `$ASSETVAULT_ROOT` (default `/workspace/assetvault`), creates `$ASSETVAULT_ROOT/.venv`, installs `requirements.txt`, and creates `blobs/`, `exports/`, and `connectors/` with mode 0700. It never modifies `vault.db.enc`, `vault.meta.json`, `audit.log.enc`, or `blobs/`. You can run it again safely: it only adds missing code files and dependencies.

To upgrade, run `./install.sh --update`. It replaces only the code files (`bin/`, `ui/`, `VERSION`). If a release changes `requirements.txt`, run `./install.sh` again afterwards.

## Use

```bash
export ASSETVAULT_ROOT=/workspace/assetvault
read -rs ASSETVAULT_PASSPHRASE && export ASSETVAULT_PASSPHRASE   # type the passphrase, nothing is echoed
cd "$ASSETVAULT_ROOT"

# one-time: create the vault (rooms, categories, value threshold that requires a receipt/photo)
.venv/bin/python -c 'import sys; sys.path.insert(0, "bin"); import avcore; avcore.init(["Office"], ["Computers", "Networking", "Other"], 500)'

.venv/bin/python bin/dashboard.py   # prints the port; the tokenized URL is in .dashboard_url
bin/lock.sh                         # stop the dashboard
```

### Tests

- `bin/selftest.py` creates a vault in `$ASSETVAULT_ROOT`, so run it only against an empty, throwaway root.
- `bin/test_dashboard.py` runs end to end against its own temporary vault with fake data. It uses the code and `.venv` in `$ASSETVAULT_ROOT`.

## License

MIT. See `LICENSE`.
