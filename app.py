"""Outbound-only SMB importer. One process owns the persistent volume."""
import ftplib
import hashlib
import json
import ntpath
import os
import posixpath
import secrets
import sqlite3
import stat
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
import smbclient
from cryptography.fernet import Fernet
from flask import Flask, abort, redirect, render_template, request, session
from requests_toolbelt.multipart.encoder import MultipartEncoder

API = "https://app.visiondoc.ai/api"
DATA = Path(os.environ.get("APPLIANCE_DATA", "/data"))
DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
os.umask(0o077)
KEY = DATA / "key"
if not KEY.exists():
    with KEY.open("xb") as f:
        f.write(Fernet.generate_key())
FERNET = Fernet(KEY.read_bytes())
CONFIG = DATA / "configuration.enc"
DB = DATA / "ledger.sqlite"
# Stay under the agent ingest body cap. A lower MAX_FILE_BYTES is kept; a higher one is not.
UPLOAD_LIMIT = 64 * 1024 * 1024
try:
    _requested = int(os.environ.get("MAX_FILE_BYTES", "") or UPLOAD_LIMIT)
except ValueError:
    _requested = UPLOAD_LIMIT
MAX_BYTES = UPLOAD_LIMIT if _requested < 1 else min(_requested, UPLOAD_LIMIT)
PROTOCOLS = ("smb", "sftp", "ftps", "webdav")
CONTROL = threading.RLock()
WAKE = threading.Event()
STATE = {"running": False, "message": "Connect your company account to begin.", "last_scan": None}


def connect():
    c = sqlite3.connect(DB, timeout=30)
    c.row_factory = sqlite3.Row
    return c


with connect() as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS sent(hash TEXT PRIMARY KEY,job_id TEXT NOT NULL,created REAL NOT NULL);
    CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,bytes INTEGER,status TEXT,job_id TEXT,message TEXT,updated REAL);
    """)


def config():
    with CONTROL:
        if not CONFIG.exists():
            return {}
        value = json.loads(FERNET.decrypt(CONFIG.read_bytes()))
        if value.get("target") != API:
            raise RuntimeError("This volume was created for a different VisionDoc address. Use a separate volume.")
        return value


def save(value):
    value = dict(value, target=API)
    with CONTROL:
        fd, name = tempfile.mkstemp(dir=DATA)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(FERNET.encrypt(json.dumps(value).encode()))
                f.flush()
                os.fsync(f.fileno())
            os.replace(name, CONFIG)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    WAKE.set()


# Validate volume ownership before serving or starting background work.
config()
app = Flask(__name__, template_folder=str(Path(__file__).parent / "templates"))
app.secret_key = KEY.read_bytes()
app.config.update(MAX_CONTENT_LENGTH=32768, SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=os.environ.get("UI_SECURE_COOKIE") == "1", PERMANENT_SESSION_LIFETIME=86400 * 30,
                  TRUSTED_HOSTS=os.environ.get("UI_HOSTS", "localhost,127.0.0.1,[::1]").split(","))


@app.before_request
def protect():
    if request.routing_exception:
        return
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    if request.method == "POST" and not secrets.compare_digest(request.form.get("csrf", ""), session["csrf"]):
        abort(403)
    if request.endpoint not in {"index", "login", "static", "health"} and not session.get("authenticated"):
        abort(401)


@app.after_request
def secure(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'"
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def index():
    cfg = config() if session.get("authenticated") else {}
    with connect() as c:
        files = [dict(row) for row in c.execute("SELECT * FROM files ORDER BY updated DESC LIMIT 200")] if cfg else []
        count = c.execute("SELECT COUNT(*) FROM sent").fetchone()[0] if cfg else 0
    return render_template("index.html", cfg=cfg,
                           files=files, count=count, state=STATE.copy(), csrf=session["csrf"],
                           error=session.pop("error", None))


ATTEMPTS = []


@app.post("/login")
def login():
    now = time.monotonic()
    with CONTROL:
        ATTEMPTS[:] = [stamp for stamp in ATTEMPTS if now - stamp < 300]
        if len(ATTEMPTS) >= 10:
            abort(429)
        ATTEMPTS.append(now)
    try:
        # Never follow redirects with credentials or accept user-provided cloud URLs.
        with requests.Session() as cloud:
            response = cloud.post(API + "/auth/login", json={"user_id": request.form["email"].strip(),
                                  "password": request.form["password"]}, timeout=30, allow_redirects=False)
            if response.status_code != 200:
                raise ValueError("Sign-in failed. Check your company email and password.")
            identity = response.json()
            if identity.get("must_change_password") or identity.get("mfa_required"):
                raise ValueError("Complete the required account security steps on the company website first.")
            previous = config()
            if previous:
                if identity.get("tenant_id") != previous["tenant_id"] or "settings:edit" not in identity.get("permissions", []):
                    raise ValueError("Sign in as an administrator of the connected company.")
            else:
                response = cloud.post(API + "/integrations/nas/pair", timeout=30, allow_redirects=False)
                if response.status_code == 403:
                    raise ValueError("Folder import must be enabled for this company, and pairing requires an administrator.")
                if response.status_code != 200:
                    raise ValueError("Cannot pair this appliance. Check that the server supports SMB pairing.")
                paired = response.json()
                save({"tenant_id": paired["tenant_id"], "token": paired["token"],
                      "token_id": paired["token_id"], "email": request.form["email"].strip(), "enabled": False})
        session.clear()
        session["authenticated"] = True
        session["csrf"] = secrets.token_urlsafe(32)
        session.permanent = True
    except (requests.RequestException, KeyError, ValueError) as exc:
        session["error"] = str(exc) if isinstance(exc, ValueError) else "Cannot reach the company website. Try again."
    return redirect("/")


@app.post("/logout")
def logout():
    session.clear()
    return redirect("/")


def smb_options(cfg):
    return {"username": cfg["smb_user"], "password": cfg["smb_password"],
            "encrypt": True, "connection_timeout": 20}


def protocol_of(cfg):
    value = (cfg.get("protocol") or "smb").strip()
    if value not in PROTOCOLS:
        raise ValueError("Choose SMB, SFTP, FTPS or WebDAV.")
    return value


def normalize_location(protocol, raw):
    """Canonical encrypted folder address. Credentials stay in their own fields."""
    protocol = protocol_of({"protocol": protocol})
    if protocol == "smb":
        return normalize_share(raw)
    text = (raw or "").strip()
    scheme = {"sftp": "sftp", "ftps": "ftps", "webdav": "https"}[protocol]
    default_port = {"sftp": 22, "ftps": 21, "webdav": 443}[protocol]
    label = {"sftp": "SFTP", "ftps": "FTPS", "webdav": "WebDAV"}[protocol]
    example = {"sftp": "sftp://files.example/inbox", "ftps": "ftps://files.example/inbox",
               "webdav": "https://files.example/inbox"}[protocol]
    message = f"Enter a {label} folder, for example {example}, without a trailing slash."
    if "\\" in text or text.startswith("//"):
        raise ValueError(message)
    if "://" not in text:
        text = f"{scheme}://{text}"
    parsed = urlparse(text)
    if parsed.scheme != scheme or parsed.username or parsed.password or not parsed.hostname:
        raise ValueError(message)
    segments = [unquote(part) for part in parsed.path.split("/")]
    segments = [part for part in segments if part]
    if not segments or any(part in {".", ".."} or "\x00" in part or "\\" in part for part in segments):
        raise ValueError(message)
    if parsed.path.endswith("/"):
        raise ValueError(message)
    port = parsed.port or default_port
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}/{'/'.join(segments)}"


def relative_of(cfg, path):
    if protocol_of(cfg) == "smb":
        relative = ntpath.relpath(path, cfg["share"])
    else:
        root = urlparse(cfg["share"]).path
        child = urlparse(path).path if "://" in path else path
        relative = posixpath.relpath(child, root)
    if relative in {"", "."} or relative.startswith("..") or "/.." in relative or "\\.." in relative:
        raise ValueError("File is outside the selected folder.")
    return relative


class RemoteStat:
    def __init__(self, size, mtime):
        self.st_size = int(size)
        self.st_mtime = float(mtime)
        self.st_mtime_ns = int(self.st_mtime * 1_000_000_000)


class SftpSource:
    def __init__(self, cfg, accept_new_key):
        import paramiko
        parsed = urlparse(cfg["share"])
        self.host = parsed.hostname
        self.port = parsed.port or 22
        self.root = parsed.path
        self.paramiko = paramiko
        self.client = paramiko.SSHClient()
        self.captured = None
        pin_id = f"{self.host}:{self.port}"
        pinned = cfg.get("ssh_host") == pin_id and cfg.get("ssh_host_key") and cfg.get("ssh_host_key_type")
        if not accept_new_key and not pinned:
            raise ValueError("Save this SFTP folder again so its server key can be checked.")
        if not accept_new_key:
            import base64
            key = paramiko.PKey.from_type_string(cfg["ssh_host_key_type"], base64.b64decode(cfg["ssh_host_key"]))
            lookup = f"[{self.host}]:{self.port}" if self.port != 22 else self.host
            self.client.get_host_keys().add(lookup, cfg["ssh_host_key_type"], key)
        else:
            source = self

            class Capture(paramiko.MissingHostKeyPolicy):
                def missing_host_key(self, client, hostname, key):
                    source.captured = (key.get_name(), key.get_base64())
                    client.get_host_keys().add(hostname, key.get_name(), key)

            self.client.set_missing_host_key_policy(Capture())
        # The first save pins the key. Later scans reject a different key.
        self.client.connect(self.host, self.port, cfg["smb_user"], cfg["smb_password"], timeout=20,
                            banner_timeout=20, auth_timeout=20, allow_agent=False, look_for_keys=False)
        self.sftp = self.client.open_sftp()

    def close(self):
        try:
            self.sftp.close()
        finally:
            self.client.close()

    def probe(self):
        self.sftp.listdir(self.root)

    def pin(self):
        if not self.captured:
            return None
        return (f"{self.host}:{self.port}", self.captured[0], self.captured[1])

    def files(self):
        pending = [self.root]
        while pending:
            folder = pending.pop()
            for attr in self.sftp.listdir_attr(folder):
                name = attr.filename
                if name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
                    continue
                mode = attr.st_mode or 0
                child = folder.rstrip("/") + "/" + name
                if stat.S_ISLNK(mode):
                    continue
                if stat.S_ISDIR(mode):
                    pending.append(child)
                elif stat.S_ISREG(mode):
                    yield self._url(child)

    def _url(self, path):
        host = f"[{self.host}]" if ":" in self.host else self.host
        suffix = "" if self.port == 22 else f":{self.port}"
        return f"sftp://{host}{suffix}{path}"

    def stat(self, url):
        attr = self.sftp.stat(urlparse(url).path)
        return RemoteStat(attr.st_size, attr.st_mtime)

    def open(self, url):
        return self.sftp.open(urlparse(url).path, "rb")


class FtpsSource:
    def __init__(self, cfg):
        parsed = urlparse(cfg["share"])
        self.host = parsed.hostname
        self.port = parsed.port or 21
        self.root = parsed.path
        self.ftp = ftplib.FTP_TLS()
        self.ftp.connect(self.host, self.port, timeout=20)
        self.ftp.auth()
        self.ftp.login(cfg["smb_user"], cfg["smb_password"])
        self.ftp.prot_p()

    def close(self):
        try:
            self.ftp.quit()
        except Exception:
            self.ftp.close()

    def probe(self):
        list(self.ftp.mlsd(self.root))

    def pin(self):
        return None

    def files(self):
        pending = [self.root]
        while pending:
            folder = pending.pop()
            try:
                listed = list(self.ftp.mlsd(folder))
            except ftplib.error_perm as exc:
                raise ValueError("This FTPS server must support MLSD so folders and files can be told apart.") from exc
            for name, facts in listed:
                kind = (facts.get("type") or "").lower()
                if kind in {"cdir", "pdir"} or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
                    continue
                child = folder.rstrip("/") + "/" + name
                if kind == "dir":
                    pending.append(child)
                elif kind == "file":
                    yield self._url(child)

    def _url(self, path):
        host = f"[{self.host}]" if ":" in self.host else self.host
        suffix = "" if self.port == 21 else f":{self.port}"
        return f"ftps://{host}{suffix}{path}"

    def stat(self, url):
        path = urlparse(url).path
        size = self.ftp.size(path)
        reply = self.ftp.sendcmd("MDTM " + path).split()[-1]
        mtime = datetime.strptime(reply, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc).timestamp()
        if size is None:
            raise ValueError("The server did not report a file size.")
        return RemoteStat(size, mtime)

    def open(self, url):
        tmp = tempfile.TemporaryFile(dir=DATA)
        written = 0

        def write(chunk):
            nonlocal written
            written += len(chunk)
            if written > MAX_BYTES:
                raise UploadTooLarge()
            tmp.write(chunk)

        try:
            self.ftp.retrbinary("RETR " + urlparse(url).path, write)
        except Exception:
            tmp.close()
            raise
        tmp.seek(0)
        return tmp


def _xml_child(node, name):
    if node is None:
        return None
    for child in list(node):
        if child.tag.rsplit("}", 1)[-1] == name:
            return child
    return None


def webdav_entries(payload, folder):
    root = ET.fromstring(payload)
    folder = unquote(urlparse(folder).path if "://" in folder else folder).rstrip("/")
    found = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1] != "response":
            continue
        href_node = _xml_child(node, "href")
        href = href_node.text if href_node is not None and href_node.text else ""
        path = unquote(urlparse(href).path if "://" in href else href)
        prop = _xml_child(_xml_child(node, "propstat"), "prop")
        if prop is None or path.rstrip("/") == folder:
            continue
        is_dir = _xml_child(_xml_child(prop, "resourcetype"), "collection") is not None
        name = posixpath.basename(path.rstrip("/"))
        if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
            continue
        length_node = _xml_child(prop, "getcontentlength")
        modified_node = _xml_child(prop, "getlastmodified")
        length = length_node.text.strip() if length_node is not None and length_node.text else ""
        modified = modified_node.text.strip() if modified_node is not None and modified_node.text else ""
        found.append((path if path.startswith("/") else "/" + path, "dir" if is_dir else "file", length, modified))
    return found


class WebdavSource:
    def __init__(self, cfg):
        parsed = urlparse(cfg["share"])
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        self.origin = f"https://{host}" if parsed.port in (None, 443) else f"https://{host}:{parsed.port}"
        self.host = parsed.hostname
        self.port = parsed.port or 443
        self.root = parsed.path
        self.auth = (cfg["smb_user"], cfg["smb_password"])
        self.http = requests.Session()

    def close(self):
        self.http.close()

    def pin(self):
        return None

    def _request(self, method, path, **kwargs):
        response = self.http.request(method, self.origin + path, auth=self.auth, timeout=30, allow_redirects=False, **kwargs)
        if response.is_redirect or response.status_code in {301, 302, 303, 307, 308}:
            response.close()
            raise ValueError("The WebDAV server sent a redirect. Enter the folder's own HTTPS address.")
        if response.status_code in {401, 403}:
            response.close()
            raise ValueError("The folder rejected this username or password.")
        return response

    def _describe(self, path, depth):
        body = b'<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/><d:getlastmodified/></d:prop></d:propfind>'
        response = self._request("PROPFIND", path, data=body, headers={"Depth": depth, "Content-Type": "application/xml"})
        try:
            if response.status_code != 207:
                raise ValueError("Cannot read this WebDAV folder.")
            return webdav_entries(response.content, path)
        finally:
            response.close()

    def probe(self):
        self._describe(self.root, "1")

    def files(self):
        pending = [self.root]
        while pending:
            folder = pending.pop()
            for path, kind, _length, _modified in self._describe(folder, "1"):
                if kind == "dir":
                    pending.append(path if path.startswith("/") else "/" + path)
                else:
                    yield self.origin + (path if path.startswith("/") else "/" + path)

    def stat(self, url):
        path = urlparse(url).path
        entries = self._describe(posixpath.dirname(path) or "/", "1")
        match = [item for item in entries if unquote(item[0]).rstrip("/") == path.rstrip("/")]
        if not match or not match[0][2] or not match[0][3]:
            raise ValueError("The server did not report this file's size and time.")
        mtime = parsedate_to_datetime(match[0][3]).timestamp()
        return RemoteStat(match[0][2], mtime)

    def open(self, url):
        response = self._request("GET", urlparse(url).path, stream=True)
        if response.status_code != 200:
            response.close()
            raise ValueError("Cannot read this file.")
        tmp = tempfile.TemporaryFile(dir=DATA)
        written = 0
        try:
            for chunk in response.iter_content(1024 * 1024):
                if not chunk:
                    continue
                written += len(chunk)
                if written > MAX_BYTES:
                    raise UploadTooLarge()
                tmp.write(chunk)
        except Exception:
            tmp.close()
            raise
        finally:
            response.close()
        tmp.seek(0)
        return tmp


@contextmanager
def remote_source(cfg, accept_new_key=False):
    kind = protocol_of(cfg)
    if kind == "sftp":
        source = SftpSource(cfg, accept_new_key)
    elif kind == "ftps":
        source = FtpsSource(cfg)
    elif kind == "webdav":
        source = WebdavSource(cfg)
    else:
        raise ValueError("Choose SMB, SFTP, FTPS or WebDAV.")
    try:
        yield source
    finally:
        source.close()


def explain_remote_error(exc):
    name = type(exc).__name__
    if name in {"AuthenticationException", "BadAuthenticationType"}:
        return ValueError("The folder rejected this username or password.")
    if name == "BadHostKeyException":
        return ValueError("The server key changed. Save the folder again only if you trust this server.")
    return exc


def test_remote(cfg, accept_new_key):
    try:
        with remote_source(cfg, accept_new_key) as source:
            source.probe()
            return source.pin()
    except ValueError:
        raise
    except Exception as exc:
        raise explain_remote_error(exc) from exc


def normalize_share(raw):
    path = raw.strip().replace("/", "\\")
    parts = path[2:].split("\\") if path.startswith("\\\\") else []
    if len(parts) < 2 or any(p in {"", ".", ".."} for p in parts) or any("\x00" in p for p in parts):
        raise ValueError("Enter a complete SMB path, for example \\\\server\\share\\folder, without a trailing slash.")
    return path


@app.post("/share")
def share():
    try:
        if STATE["running"]:
            raise ValueError("Pause the import and wait for the current file before changing the folder.")
        protocol = (request.form.get("protocol") or "smb").strip()
        if protocol not in PROTOCOLS:
            raise ValueError("Choose SMB, SFTP, FTPS or WebDAV.")
        user = request.form.get("smb_user", "").strip()
        password = request.form.get("smb_password", "")
        if not user or password == "":
            raise ValueError("Enter the username and password for this folder.")
        location = normalize_share(request.form.get("share", "")) if protocol == "smb" else normalize_location(protocol, request.form.get("share", ""))
        current = config()
        updated = {key: current[key] for key in ("tenant_id", "token", "token_id", "email") if key in current}
        updated.update(protocol=protocol, share=location, smb_user=user, smb_password=password, enabled=False)
        if protocol == "smb":
            # Listing tests credentials, share access and SMB encryption before persisting.
            iterator = smbclient.scandir(updated["share"], **smb_options(updated))
            try:
                next(iterator, None)
            finally:
                iterator.close()
        else:
            pinned = test_remote(updated, accept_new_key=protocol == "sftp")
            if pinned:
                updated["ssh_host"], updated["ssh_host_key_type"], updated["ssh_host_key"] = pinned
        save(updated)
        STATE["message"] = "Folder connected. Start importing when ready."
    except ValueError as exc:
        session["error"] = str(exc)
    except Exception:
        chosen = (request.form.get("protocol") or "smb").strip()
        session["error"] = "Cannot read this SMB share. Check the path, credentials, network and SMB 3 encryption support." if chosen == "smb" else "Cannot read this folder. Check the address, credentials, network and encryption support."
    return redirect("/")


@app.post("/run")
def run():
    cfg = config()
    if not cfg.get("share"):
        abort(400)
    cfg["enabled"] = request.form.get("action") == "start"
    save(cfg)
    STATE["message"] = "Import scheduled." if cfg["enabled"] else "Paused. Any current file will finish."
    return redirect("/")


def record(path, size, status, job="", message=""):
    with connect() as c:
        c.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?,?,?)", (path, size, status, job, message, time.time()))


def walk(root, options):
    pending = [root]
    while pending:
        folder = pending.pop()
        for entry in smbclient.scandir(folder, **options):
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                pending.append(entry.path)
            elif entry.is_file(follow_symlinks=False):
                yield entry.path


class UploadTooLarge(Exception):
    pass


def limit_message():
    return f"File exceeds the {MAX_BYTES // (1024 * 1024)} MB upload limit and was not uploaded."


def copy_bounded(stream, staging):
    digest = hashlib.sha256()
    size = 0
    while chunk := stream.read(1024 * 1024):
        if size + len(chunk) > MAX_BYTES:
            return None
        size += len(chunk)
        digest.update(chunk)
        staging.write(chunk)
    return size, digest.hexdigest()


def upload_staged(cfg, relative, name, staging, size, content_hash):
    with connect() as c:
        sent = c.execute("SELECT job_id FROM sent WHERE hash=?", (content_hash,)).fetchone()
    if sent:
        record(relative, size, "unchanged", sent["job_id"])
        return
    staging.seek(0)
    body = MultipartEncoder(fields={"rel_path": relative, "file": (name, staging, "application/octet-stream")})
    response = requests.post(API + "/agent/ingest", data=body,
                             headers={"Authorization": "Bearer " + cfg["token"], "Content-Type": body.content_type},
                             timeout=(20, 600), allow_redirects=False)
    if response.status_code != 200:
        record(relative, size, "error", message=f"Server returned HTTP {response.status_code}; will retry on the next scan.")
        return
    result = response.json()
    job = result.get("job_id")
    if not job:
        raise ValueError("The server did not confirm a document ID.")
    with connect() as c:
        c.execute("INSERT OR IGNORE INTO sent VALUES (?,?,?)", (content_hash, job, time.time()))
    record(relative, size, "duplicate" if result.get("duplicate") else "uploaded", job)


def import_remote_file(path, cfg):
    relative = relative_of(cfg, path)
    with remote_source(cfg) as source:
        before = source.stat(path)
        if before.st_size > MAX_BYTES:
            record(relative, before.st_size, "error", message=limit_message())
            return
        if time.time() - before.st_mtime < 10:
            record(relative, before.st_size, "waiting", message="Waiting for file writing to finish.")
            return
        with tempfile.TemporaryFile(dir=DATA) as staging:
            try:
                with source.open(path) as incoming:
                    bounded = copy_bounded(incoming, staging)
            except UploadTooLarge:
                record(relative, before.st_size, "error", message=limit_message())
                return
            if bounded is None:
                record(relative, before.st_size, "error", message=limit_message())
                return
            size, content_hash = bounded
            after = source.stat(path)
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or size != after.st_size:
                record(relative, size, "waiting", message="File changed while being read; retrying next scan.")
                return
            upload_staged(cfg, relative, posixpath.basename(urlparse(path).path), staging, size, content_hash)


def import_file(path, cfg):
    if protocol_of(cfg) != "smb":
        import_remote_file(path, cfg)
        return
    options = smb_options(cfg)
    relative = ntpath.relpath(path, cfg["share"])
    before = smbclient.stat(path, follow_symlinks=False, **options)
    if before.st_size > MAX_BYTES:
        record(relative, before.st_size, "error", message=limit_message())
        return
    if time.time() - before.st_mtime < 10:
        record(relative, before.st_size, "waiting", message="Waiting for file writing to finish.")
        return
    with tempfile.TemporaryFile(dir=DATA) as staging:
        with smbclient.open_file(path, mode="rb", **options) as source:
            bounded = copy_bounded(source, staging)
        if bounded is None:
            record(relative, before.st_size, "error", message=limit_message())
            return
        size, content_hash = bounded
        after = smbclient.stat(path, follow_symlinks=False, **options)
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or size != after.st_size:
            record(relative, size, "waiting", message="File changed while being read; retrying next scan.")
            return
        upload_staged(cfg, relative, ntpath.basename(path), staging, size, content_hash)


def scan_paths(cfg):
    if protocol_of(cfg) == "smb":
        yield from walk(cfg["share"], smb_options(cfg))
        return
    with remote_source(cfg) as source:
        yield from source.files()


def scan():
    cfg = config()
    if not cfg.get("enabled") or not cfg.get("share"):
        return
    STATE.update(running=True, message="Reading the folder…")
    try:
        response = requests.get(API + "/agent/health", headers={"Authorization": "Bearer " + cfg["token"]}, timeout=20, allow_redirects=False)
        if response.status_code != 200:
            STATE["message"] = f"Connection not authorised or unavailable (HTTP {response.status_code}). Settings retained; retrying later."
            return
        for path in scan_paths(cfg):
            if not config().get("enabled"):
                break
            try:
                import_file(path, cfg)
            except Exception:
                record(relative_of(cfg, path), 0, "error", message="Could not read or upload this file; retrying next scan.")
        STATE.update(message="Scan complete. New and changed content will be checked again automatically.", last_scan=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
    except Exception as exc:
        if type(exc).__name__ == "BadHostKeyException":
            STATE["message"] = "The server key changed. Settings retained. Save the folder again only if you trust this server."
        else:
            STATE["message"] = "Folder unavailable. Settings retained; retrying automatically."
    finally:
        STATE["running"] = False


def worker():
    while True:
        WAKE.clear()
        scan()
        WAKE.wait(60)


if __name__ == "__main__":
    import fcntl
    instance_lock = (DATA / "instance.lock").open("a")
    fcntl.flock(instance_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    from waitress import serve
    threading.Thread(target=worker, daemon=True).start()
    serve(app, host="0.0.0.0", port=8080, threads=4, max_request_body_size=32768)
