# VisionDoc folder importer

This repository is only the folder-importer image. It does not contain the VisionDoc application.

Open a local setup website, sign in with a company administrator account, and choose SMB, SFTP, FTPS or WebDAV. Enter a folder and read-only credentials. The appliance recursively reads files and uploads them through the normal document pipeline. It never changes the source files.

## Start

Requires Docker Compose and SMB 3 encryption support on the NAS. Build the image for your machine (Intel/AMD or ARM):

```sh
ENVIRONMENT=prod docker compose up -d --build
```

Open **http://localhost:8787**. Sign in with the account for the selected environment. Choose a protocol and enter the folder, username and password. SMB uses `\\server\share\folder`. SFTP, FTPS and WebDAV use `sftp://`, `ftps://` and `https://` addresses. **Test connection and save**, then **Start import**. Refresh the page to see progress.

Supported combinations:

| Environment | Cloud endpoint | Image |
|---|---|---|
| dev | https://app.dev.visiondoc.ai | `visiondoc-smb:dev` |
| staging | https://app.stg.visiondoc.ai | `visiondoc-smb:staging` |
| prod | https://app.visiondoc.ai | `visiondoc-smb:prod` |

Use `UI_PORT=8788` when running a second appliance. Each environment has a separate Compose project and named volume. Images for staging and prod do not deploy the cloud application; its server must separately support the pairing API.

## Restart and credentials

`docker compose restart` or a machine restart retains the encrypted settings, agent token and SHA-256 ledger in the named `state` volume. Docker must start automatically on that machine. Import resumes without entering account credentials again. Browser sign-in lasts up to 30 days. Signing out hides this screen and does not stop import. Pause stops the scan.

The company password is used only for cloud sign-in and is not saved. The server issues a revocable, tenant-bound agent token. Folder credentials must be retained to reconnect: they are encrypted on disk, with the encryption key in the same protected volume. An SFTP server key is pinned on the first successful save and later scans reject a different key. Someone who controls the host/volume can decrypt them. Back up the complete volume; do not run `docker compose down -v` unless intentionally resetting the appliance. A volume refuses to open against a different environment.

The UI binds to localhost by default. For remote management use a secured HTTPS reverse proxy, set `UI_HOSTS` to the exact hostname, and configure secure cookies before exposing the UI. Do not expose the setup port directly to the internet.

## Enablement

New appliance pairing is **off by default**. An operator must explicitly set `DLP_SMB_ENABLED_TENANTS` on the cloud API to a comma-separated list of permitted tenant IDs; no wildcard is accepted. Company administrators can then pair. Removing a tenant disables that appliance's health/upload calls immediately. Staff can revoke its token through the existing agent-token administration API. Legacy NAS tokens retain their existing behaviour.

No tenants are enabled by this package. The owner's requested enable-only scope still needs to be supplied.

## Import behaviour

- The ledger hashes file contents, so unchanged copies and renamed files upload once per company. The server also deduplicates retries after a lost response, and serialises simultaneous identical uploads using an OS file lock.
- Different contents with the same basename use separate storage directories. A changed source file becomes a **new document**. This importer does not merge it into an existing document's version history.
- A file must be at least 10 seconds old and unchanged in size/time while read. Symlinks are skipped. Files larger than 64 MB are not uploaded. `MAX_FILE_BYTES` can set a lower cap, not a higher one. Empty files are rejected by the server.
- Failed connections/uploads retry on the next 60-second scan; successes are recorded only after the server returns a document ID. Interrupted server-side imports resume their existing job.
- Deleting a NAS file does not delete its cloud document. The local ledger retains successful hashes even if somebody subsequently deletes a cloud document; a deliberate re-import requires resetting that ledger.
- All normal cloud storage limits, licensing and document processing rules still apply. A successful upload does not imply every file format has OCR support.
- Uses outbound encrypted connections only: SMB 3, SFTP, explicit FTPS, or WebDAV over HTTPS. No privileged container, host mount or inbound port forward. Plain FTP and plain HTTP are rejected.

## Validation

```sh
python -m unittest discover -s tests -v
# Optional disposable Samba fixture (Docker required):
APPLIANCE_TEST_IMAGE=visiondoc-smb:dev-arm64 python tests/samba/run.py
```

The backend tests separately cover disabled tenants, admin-only pairing, token revocation, tenant isolation, duplicate retry/rename, same-name safety, interrupted jobs and concurrent requests. A Samba fixture test verifies real SMB 3 encrypted recursive reads and a new container resuming the same volume without uploading existing content again. Its cloud response is stubbed; backend request tests exercise the actual API router.

Upstream interfaces: [smbprotocol](https://github.com/jborean93/smbprotocol), [Docker volumes](https://docs.docker.com/reference/compose-file/volumes/).
