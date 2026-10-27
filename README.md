# AssetVault

AssetVault is an encrypted, local-first inventory for IT assets, backup status, and insurance documentation. It keeps the database, attachments, and audit log in encrypted files on your own machine. A dashboard listens only on localhost. A small command line syncs read-only device directories into a staged merge review.

It is the storage and UI layer for a chat bot, and it also runs on its own.

## What it does today

- Encrypted item inventory: rooms, categories, serials, values, warranty, owner, OS, MAC address, asset tag, and encryption status.
- Encrypted photo and receipt attachments, stored as separate encrypted blobs.
- Backup tracking: backup history per item, an RPO target in hours, Met / At risk / Breached status, and a 30-day strip showing each day's result.
- Completeness flags (missing serial, value, receipt, photo, or room) and warranty expiry status.
- An encrypted audit log of setup, migrations, connects, syncs, imports, commits, discards, exports, dashboard start and stop, and serial reveals.
- A localhost dashboard for viewing, adding, editing, and deleting items, logging backups, attaching files, reviewing merges, and writing exports.
- Read-only connectors for Microsoft Entra ID / Intune, Active Directory (LDAPS), Jamf Pro, and any other device API through a generic REST connector.
- CSV and XLSX import that detects Intune, Entra, AD, and Jamf exports, then stages the same merge review.
- Merge review matched on serial, then MAC, then external id for that source, then a soft name and model match. Soft matches are not applied until you verify them. A sync never deletes a local item.
- Insurance PDF (and a redacted copy) plus a CSV export, written only under the vault's `exports/` directory at mode 0600.

### Still planned

- Scheduled or unattended sync. A sync runs when you start it from the command line or the Sources page.
- Write-back to a directory or MDM is intentionally not implemented. Connectors only pull.
- Tested restore on a second device. Planned. Recover the vault after a machine is lost. Export an encrypted backup of the vault. Restore that backup with a command on a fresh machine. After restore, check that the item count matches and that attachments decrypt. Keep the passphrase stored apart from the backup, never together. The docs should say to keep them apart. The restore command should remind you. `export` writes an unencrypted CSV or PDF. `import` stages a device spreadsheet. Neither copies the encrypted vault nor loads it on a fresh machine.

## Security model

- **Encrypted at rest.** The database, attachments, audit log, connector config, and staged reviews are encrypted with AES-256-GCM. The key comes from your passphrase through Argon2id (t=3, m=64 MiB, p=4), or through scrypt if `argon2-cffi` isn't installed. `vault.meta.json` holds only the KDF parameters, the salt, and an encrypted key-check value.
- **The passphrase is never stored.** It is read from `ASSETVAULT_PASSPHRASE` when the program starts.
- **Secrets are environment variables.** Client secrets and passwords are read when a connector runs. They are not written into connector config, the audit log, or exception text. Non-secret settings (URL, tenant id, client id, field mapping) are stored inside the encrypted database.
- **Decrypted data stays in memory.** Import libraries that need a scratch directory get a mode 0700 temp dir that is shredded afterward. The one plaintext you ask for is an export file under `exports/`, mode 0600.
- **Connectors are read-only.** They do not create, update, or delete directory or MDM objects. They talk only to the host you configured. There is no telemetry.
- **A sync never deletes local items.** Devices that belong to that source and are missing from the pull are flagged not seen, with a timestamp. Soft matches are never merged on their own.
- **The dashboard is bound to 127.0.0.1.** It also needs a random per-session URL token, rejects any Host header other than localhost, rejects cross-origin POSTs, and shuts down after 30 minutes idle (`ASSETVAULT_IDLE_SECONDS`). `bin/lock.sh` stops it.
- **Plaintext on disk:** `vault.meta.json` (KDF metadata only); `audit.failed_unlocks` (timestamps only); `.dashboard_url` / `.dashboard.pid` while the dashboard is running (mode 0600); and files you export into `exports/`.

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

The installer copies `bin/` and `ui/` into `$ASSETVAULT_ROOT` (default `/workspace/assetvault`), creates `$ASSETVAULT_ROOT/.venv`, installs `requirements.txt`, and creates `blobs/`, `exports/`, and `connectors/` with mode 0700. It never modifies `vault.db.enc`, `vault.meta.json`, `audit.log.enc`, or `blobs/`.

`./install.sh --update` replaces code files only (`bin/`, `ui/`, `VERSION`), including connector modules. It does not install Python packages and it does not touch vault data. An existing 0.1.0 vault opens and upgrades in place the next time you unlock it. If `requirements.txt` changed, run `./install.sh` once without `--update` so the venv picks up `ldap3`, `openpyxl`, `reportlab`, and `pillow`.

## Use

```bash
export ASSETVAULT_ROOT=/workspace/assetvault
read -rs ASSETVAULT_PASSPHRASE && export ASSETVAULT_PASSPHRASE
cd "$ASSETVAULT_ROOT"

.venv/bin/python -c 'import sys; sys.path.insert(0, "bin"); import avcore; avcore.init(["Office"], ["Computers", "Networking", "Other"], 500)'

.venv/bin/python bin/dashboard.py
bin/lock.sh
```

Commands below print JSON only. From a git checkout, `python -m assetvault.connect` works when the repo root is on `PYTHONPATH`. After install, the same commands are `python bin/connect.py`.

```bash
.venv/bin/python bin/connect.py connectors
.venv/bin/python bin/connect.py entra --config entra.json --test
.venv/bin/python bin/connect.py sync entra
.venv/bin/python bin/connect.py import devices.csv
.venv/bin/python bin/connect.py commit --review 1 --verify 0
.venv/bin/python bin/connect.py discard --review 1
.venv/bin/python bin/connect.py disconnect entra
.venv/bin/python bin/connect.py export csv
.venv/bin/python bin/connect.py export pdf
.venv/bin/python bin/connect.py export pdf-redacted
```

`--test` pulls up to five devices and prints the mapped fields with serials masked to the last four characters. `sync` and `import` stage a review. They do not change items until `commit`. Commit applies exact matches, new devices, and soft matches you passed with `--verify`. Discard drops the review and leaves items alone.

`ASSETVAULT_ACTOR` is optional. It is stored on audit lines and defaults to `owner`.

## Connectors

Each connector reads non-secret settings from a JSON object and reads its secret from the environment at call time. Putting a secret in the JSON is refused and nothing is saved. If the directory rejects the login, the source is still saved with health `Auth failed` so you can fix the environment and use Sync now.

Health is `OK`, `Auth failed`, or `Unreachable`. The Sources page shows a red banner whenever health is set and is not `OK`, and an amber banner when the last successful or failed sync is older than 30 days.

### Entra ID and Intune

Register an application in the Microsoft Entra admin center. Create a client secret and store it only in `ASSETVAULT_GRAPH_SECRET`.

Grant these **application** permissions (client credentials cannot use delegated permissions) and grant admin consent:

- `Device.Read.All` — read `GET /devices`
- `DeviceManagementManagedDevices.Read.All` — read `GET /deviceManagement/managedDevices`

Do not grant `Device.ReadWrite.All`, `DeviceManagementManagedDevices.ReadWrite.All`, or any permission that can change, wipe, or retire a device.

```json
{"name": "Contoso", "tenant_id": "contoso.onmicrosoft.com", "client_id": "00000000-0000-0000-0000-000000000000"}
```

`tenant_id` may be the directory id or the tenant domain. If Intune is not permitted, Entra devices are still imported and the detail notes that Intune was skipped. Paging follows `@odata.nextLink`. HTTP 429 waits for `Retry-After` (capped at 30 seconds).

### Active Directory

Create a normal user such as `svc-assetvault`. Put its password only in `ASSETVAULT_AD_PASSWORD`.

- Do not add it to Domain Admins, Account Operators, or any group that can write, reset passwords, or delegate control.
- Do not grant write access on computer objects.
- Use LDAPS on port 636. The machine running AssetVault must trust the domain controller certificate. There is no option to skip certificate checks.
- Authenticated users can often read computer objects. If the directory is locked down, grant this account **Read all properties** on the computer objects in the OU you use as the base DN.

```json
{"name": "Contoso AD", "server": "dc1.contoso.example", "base_dn": "OU=Computers,DC=contoso,DC=example", "bind_user": "CN=svc-assetvault,OU=Service,DC=contoso,DC=example"}
```

`server` is a hostname (LDAPS 636), `ldaps://host`, or `host:636`. `ldap://` and port 389 are refused unless `allow_insecure` is the boolean `true` (the string `"true"` and the number `1` do not count). The search filter is fixed to computer objects. It is not taken from config. `objectGUID` is the external id. `lastLogonTimestamp` is converted from Windows FILETIME.

### Jamf Pro

Create an API role and an API client. Put the client secret only in `ASSETVAULT_JAMF_SECRET`.

Grant only:

- **Read Computers** — `GET /api/v1/computers-inventory` and `GET /api/v3/computers-inventory`
- **Read Mobile Devices** — `GET /api/v2/mobile-devices/detail`

Do not grant Create Computers, Update Computers, Delete Computers, Send Computer Unmanage Command, Send Computer Wipe Command, View Disk Encryption Recovery Key, or the mobile-device equivalents of those write, wipe, or recovery-key privileges.

```json
{"name": "Contoso Jamf", "url": "https://contoso.jamfcloud.com", "client_id": "your-api-client-id"}
```

The pull uses `/api/v1/computers-inventory` and, if that route answers 404, `/api/v3/computers-inventory`. Sections requested are GENERAL, HARDWARE, OPERATING_SYSTEM, DISK_ENCRYPTION, and USER_AND_LOCATION. FileVault state is read from the inventory record. Recovery-key routes are never called. If mobile devices are not permitted, computers are still imported.

### Other device APIs

`generic_rest` is the connector for a directory this tree does not ship a dedicated module for. It GETs JSON and maps fields. It does not POST except that the built-in Entra and Jamf connectors POST to their own token URLs.

```json
{
  "name": "Other MDM",
  "url": "https://mdm.example/api/devices",
  "auth": "bearer",
  "items_path": "data.devices",
  "pagination": "next",
  "next_path": "links.next",
  "mapping": {"name": "hostname", "serial": "serialNumber", "model": "hardware.model", "mac": "mac"}
}
```

`auth` is `none`, `bearer` (`ASSETVAULT_REST_TOKEN`), `basic` (username in config, password in `ASSETVAULT_REST_PASSWORD`), or `header` (header name in config, value in `ASSETVAULT_REST_TOKEN`). `pagination` is `none`, `next`, or `page` (`page_param`, `page_start`, optional `page_size` and `page_size_param`). Paths use dots and `[index]`. A literal key containing a dot wins over a nested path. HTTPS is required unless `allow_insecure` is boolean `true`.

Mapping keys are the normalized fields: `name`, `serial`, `mac`, `asset_tag`, `brand`, `model`, `os`, `os_version`, `assigned_user`, `last_checkin`, `encryption_status`, `managed_by`, `external_id`, `source`, `notes`.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `ASSETVAULT_ROOT` | Vault directory. Default `/workspace/assetvault`. |
| `ASSETVAULT_PASSPHRASE` | Unlocks the vault. Never stored. |
| `ASSETVAULT_IDLE_SECONDS` | Dashboard idle timeout. Default 1800. |
| `ASSETVAULT_PORT` | Dashboard port. Default 0 (an ephemeral port). |
| `ASSETVAULT_ACTOR` | Audit actor. Default `owner`. |
| `ASSETVAULT_GRAPH_SECRET` | Entra / Graph client secret. |
| `ASSETVAULT_AD_PASSWORD` | AD bind password. |
| `ASSETVAULT_JAMF_SECRET` | Jamf API client secret. |
| `ASSETVAULT_REST_TOKEN` | Generic REST bearer token, and the custom header value. |
| `ASSETVAULT_REST_PASSWORD` | Generic REST basic-auth password. |

## Adding a connector

A new device API is one module plus one registry line.

1. Add `assetvault/bin/connectors/<name>.py`. Subclass `Connector` from `connectors.base`.
2. Set `name`, `kind` (the label stored on items), and `title`.
3. Implement `pull(self, limit=None)` so it yields normalized devices from `device(...)`. `test()` pulls at most five. `describe()` returns the config keys, the secret's environment variable name, and the permissions an admin should grant.
4. Read the secret with `self.secret("ASSETVAULT_YOUR_SECRET")` inside `pull`. Do not accept it in config. Do not put it in an exception message. Add the variable name to `SECRET_ENV_NAMES` in `avcore.py` so audit scrubbing knows it.
5. Register the class in `CLASSES` in `assetvault/bin/connectors/__init__.py`.
6. Stay read-only. Use `self.http((hostname,), allow_post=False)` for GETs. POST is allowed only for the OAuth token paths the HTTP client already permits. Do not follow redirects off the configured host.

`device()` accepts `name`, `serial`, `mac`, `asset_tag`, `brand`, `model`, `os`, `os_version`, `assigned_user`, `last_checkin`, `encryption_status`, `managed_by`, `external_id`, `source`, and `notes`.

## Imports and exports

`import` reads `.csv` or `.xlsx` (`.xls` is refused). It detects an Intune "All devices" export, an Entra devices export, a `Get-ADComputer` CSV, a Jamf inventory export, or a generic sheet using the same field names as the REST mapping. The detected mapping is in the staged review before you commit. Pass `--mapping mapping.json` to replace the detected columns. The profile name stays so managed-by is still filled in when the sheet has no such column.

`export csv` writes every item column plus linked sources. Values that start with `=`, `+`, `-`, `@`, or a tab are prefixed so a spreadsheet does not treat them as formulas.

`export pdf` is an insurance schedule: totals by room and by category for purchase and replacement value, then one row per item with brand, model, serial, condition, values, a photo thumbnail decrypted in memory, and receipt names. `export pdf-redacted` keeps the photos, masks serials to the last four characters, and omits receipt names. The dashboard export buttons show the same warning and write the same files.

## Tests

Use the venv. `selftest.py` creates a vault in `$ASSETVAULT_ROOT`, so point it at an empty throwaway directory. `test_dashboard.py` and `test_connectors.py` build their own temporary vaults. `test_dashboard.py` uses the code and `.venv` in `$ASSETVAULT_ROOT`.

```bash
ASSETVAULT_ROOT=/tmp/av-self /workspace/assetvault/.venv/bin/python assetvault/bin/selftest.py
ASSETVAULT_ROOT=/workspace/assetvault /workspace/assetvault/.venv/bin/python assetvault/bin/test_dashboard.py
ASSETVAULT_ROOT=/workspace/assetvault /workspace/assetvault/.venv/bin/python assetvault/bin/test_connectors.py
```

Connector tests mock HTTP and LDAP. They do not call Microsoft, a domain controller, or Jamf.

## License

MIT. See `LICENSE`.
