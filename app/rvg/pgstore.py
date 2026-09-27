# pgstore.py — ذخیره‌سازی PostgreSQL برای RVG
#
# چه چیزهایی روی PostgreSQL نگه داشته می‌شوند:
#   • state کامل پنل (کانفیگ‌ها، ساب‌ها، نودها، کلید نودها، رمز پنل، تنظیمات)
#   • سشن‌های ورود (دیگه با ری‌استارت/چند worker بیرون انداخته نمی‌شید)
#   • SECRET_KEY پنل (اگه عوض بشه هش رمز و UUID لینک پیش‌فرض عوض می‌شن)
#   • فایل‌های کوچیک داخل DATA_DIR (توکن TCP Proxy، تاریخچه‌ی آپدیت)
#   • اسنپ‌شات ساعتی state (۴۸ نسخه‌ی آخر) برای بازگردانی دستی
#
# خودکار:
#   • نصب درایور asyncpg (اگه نصب نباشه با pip نصبش می‌کنه)
#   • ساخت جدول‌ها (با advisory lock تا چند worker هم‌زمان تداخل نکنن)
#   • انتقال یک‌باره‌ی دیتای قبلی از Redis / فایل JSON به PostgreSQL (در main.py)
#   • همگام‌سازی بین workerها/نمونه‌ها با LISTEN/NOTIFY + بررسی دوره‌ای rev
#     (روی PgBouncer/Neon pooler که LISTEN کار نمی‌کنه، بررسی دوره‌ای کافیه)
#   • اتصال مجدد خودکار اگه دیتابیس موقتاً قطع بشه
#
# آدرس دیتابیس از یکی از این متغیرها خونده می‌شه (اولی که ست شده باشه):
#   RVG_DATABASE_URL, DATABASE_URL, POSTGRES_URL, POSTGRESQL_URL,
#   DATABASE_PRIVATE_URL  — یا از PGHOST/PGUSER/PGPASSWORD/PGDATABASE/PGPORT
import asyncio
import hashlib
import importlib
import json
import logging
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

logger = logging.getLogger("RVG-Postgres")

CHANNEL = "rvg_sync"
WORKER_ID = uuid.uuid4().hex[:12]
POLL_SECONDS = float(os.environ.get("RVG_PG_POLL_SECONDS", "10"))
POOL_MAX = int(os.environ.get("RVG_PG_POOL_MAX", "5"))
SNAPSHOT_EVERY = 3600.0
SNAPSHOT_KEEP = 48
MAX_SYNC_FILE_BYTES = 1024 * 1024
DEFAULT_SYNC_FILES = (".bot_tcp_proxy_token", "update_history.json")

SCHEMA_LOCK_ID = 727274101
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS rvg_meta (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS rvg_kv (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    rev        BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT
);
CREATE TABLE IF NOT EXISTS rvg_sessions (
    token_hash TEXT PRIMARY KEY,
    expires_at DOUBLE PRECISION NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rvg_sessions_expires_idx ON rvg_sessions (expires_at);
CREATE TABLE IF NOT EXISTS rvg_files (
    name       TEXT PRIMARY KEY,
    content    BYTEA NOT NULL,
    sha256     TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS rvg_state_snapshots (
    id         BIGSERIAL PRIMARY KEY,
    value      JSONB NOT NULL,
    rev        BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO rvg_meta (key, value) VALUES ('schema_version', '1') ON CONFLICT (key) DO NOTHING;
"""

UPSERT_STATE_SQL = """
INSERT INTO rvg_kv (key, value, rev, updated_by)
VALUES ('state', $1::jsonb, 1, $2)
ON CONFLICT (key) DO UPDATE
   SET value = EXCLUDED.value,
       rev = rvg_kv.rev + 1,
       updated_at = now(),
       updated_by = EXCLUDED.updated_by
RETURNING rev
"""

# پارامترهایی که asyncpg توی DSN می‌فهمه؛ بقیه (مثل channel_binding که Neon
# اضافه می‌کنه) به‌عنوان server setting فرستاده می‌شن و اتصال رو خراب می‌کنن.
_DSN_ALLOWED_PARAMS = {
    "sslmode", "sslrootcert", "sslcert", "sslkey", "sslpassword", "sslcrl",
    "ssl_min_protocol_version", "ssl_max_protocol_version",
    "target_session_attrs", "krbsrvname", "gsslib", "host", "port",
    "user", "password", "dbname", "passfile", "service",
}


def _env_url() -> str:
    for name in ("RVG_DATABASE_URL", "DATABASE_URL", "POSTGRES_URL",
                 "POSTGRESQL_URL", "DATABASE_PRIVATE_URL"):
        val = os.environ.get(name, "").strip()
        if val and val.split(":", 1)[0].lower().startswith("postgres"):
            return val
    host = os.environ.get("PGHOST", "").strip()
    if host:
        user = quote(os.environ.get("PGUSER", "postgres"), safe="")
        pw = os.environ.get("PGPASSWORD", "")
        auth = f"{user}:{quote(pw, safe='')}" if pw else user
        port = os.environ.get("PGPORT", "5432").strip() or "5432"
        db = quote(os.environ.get("PGDATABASE", "postgres"), safe="")
        return f"postgresql://{auth}@{host}:{port}/{db}"
    return ""


def _normalize_url(url: str) -> str:
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.split("+", 1)[0].lower()  # postgresql+asyncpg -> postgresql
        if scheme == "postgres":
            scheme = "postgresql"
        query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                 if k.lower() in _DSN_ALLOWED_PARAMS]
        dropped = [k for k, _ in parse_qsl(parts.query) if k.lower() not in _DSN_ALLOWED_PARAMS]
        if dropped:
            logger.info(f"پارامترهای {dropped} از آدرس دیتابیس حذف شدند (asyncpg پشتیبانی نمی‌کند).")
        return urlunsplit((scheme, parts.netloc, parts.path, urlencode(query), ""))
    except Exception:
        return url


DATABASE_URL = _normalize_url(_env_url())
ENABLED = bool(DATABASE_URL)

asyncpg = None
BOOT = {"ok": False, "secret": None, "error": "", "files_restored": 0}

_pool = None
_listen_conn = None
_tasks: list = []
_on_state = None
_on_sessions = None
_data_dir: Path | None = None
_last_rev = 0
_last_snapshot = 0.0
_file_hashes: dict = {}
_connected = False
_last_error = ""
_state_sync_lock = None


def _safe_host() -> str:
    try:
        p = urlsplit(DATABASE_URL)
        return f"{p.hostname or '?'}:{p.port or 5432}{p.path}"
    except Exception:
        return "?"


# ── نصب خودکار درایور ──────────────────────────────────────────────────────────
def _ensure_driver() -> bool:
    global asyncpg
    if asyncpg is not None:
        return True
    try:
        import asyncpg as _apg
        asyncpg = _apg
        return True
    except ImportError:
        pass
    logger.info("درایور asyncpg نصب نیست — در حال نصب خودکار...")
    base = [sys.executable, "-m", "pip", "install", "--quiet",
            "--disable-pip-version-check", "asyncpg>=0.29"]
    last_err = ""
    for cmd in (base, base + ["--user"], base + ["--break-system-packages"]):
        try:
            subprocess.run(cmd, check=True, timeout=300, capture_output=True)
            last_err = ""
            break
        except subprocess.CalledProcessError as e:
            last_err = (e.stderr or b"").decode(errors="ignore")[-300:]
        except Exception as e:
            last_err = str(e)
    importlib.invalidate_caches()
    try:
        import site
        user_site = site.getusersitepackages()
        if user_site and user_site not in sys.path:
            site.addsitedir(user_site)
    except Exception:
        pass
    try:
        import asyncpg as _apg
        asyncpg = _apg
        logger.info("asyncpg با موفقیت نصب شد.")
        return True
    except ImportError:
        BOOT["error"] = f"نصب asyncpg ناموفق بود: {last_err}"
        logger.error(BOOT["error"])
        return False


async def _connect_one():
    return await asyncpg.connect(
        DATABASE_URL, timeout=10, command_timeout=15, statement_cache_size=0,
        server_settings={"application_name": "rvg-gateway"},
    )


async def _ensure_schema(conn):
    async with conn.transaction():
        await conn.execute(f"SELECT pg_advisory_xact_lock({SCHEMA_LOCK_ID})")
        await conn.execute(SCHEMA_SQL)


# ── راه‌اندازی هم‌زمان (موقع import) ──────────────────────────────────────────
def _safe_name(name: str) -> bool:
    return bool(name) and "/" not in name and "\\" not in name and name not in (".", "..")


def _write_local_file(name: str, content: bytes | None):
    if _data_dir is None or not _safe_name(name):
        return
    path = _data_dir / name
    if content is None:
        path.unlink(missing_ok=True)
        _file_hashes[name] = None
        return
    _data_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(content).hexdigest()
    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == digest:
        _file_hashes[name] = digest
        return
    tmp = path.with_name(path.name + ".pgtmp")
    tmp.write_bytes(content)
    if name.startswith("."):
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
    tmp.replace(path)
    _file_hashes[name] = digest


async def _boot(secret_candidate: str | None):
    last_exc = None
    for attempt in range(3):
        try:
            conn = await _connect_one()
            break
        except Exception as e:
            last_exc = e
            await asyncio.sleep(2)
    else:
        raise last_exc
    try:
        await _ensure_schema(conn)
        await conn.execute(
            "INSERT INTO rvg_meta (key, value) VALUES ('secret', $1) ON CONFLICT (key) DO NOTHING",
            secret_candidate or secrets.token_urlsafe(32),
        )
        BOOT["secret"] = await conn.fetchval("SELECT value FROM rvg_meta WHERE key = 'secret'")
        rows = await conn.fetch("SELECT name, content FROM rvg_files")
        for r in rows:
            try:
                _write_local_file(r["name"], bytes(r["content"]))
                BOOT["files_restored"] += 1
            except Exception as e:
                logger.warning(f"بازگردانی فایل {r['name']} ناموفق بود: {e}")
        BOOT["ok"] = True
    finally:
        await conn.close()


def bootstrap(data_dir: Path, secret_candidate: str | None = None) -> dict:
    """موقع import صدا زده می‌شه (قبل از ساخته شدن CONFIG): جدول‌ها رو می‌سازه،
    SECRET_KEY مشترک رو برمی‌گردونه و فایل‌های ذخیره‌شده رو توی DATA_DIR برمی‌گردونه.
    توی یک thread جدا اجرا می‌شه تا به event loop فعلی (اگه باشه) کاری نداشته باشه."""
    global _data_dir
    _data_dir = Path(data_dir)
    if not ENABLED:
        return BOOT
    if not _ensure_driver():
        return BOOT

    def runner():
        try:
            asyncio.run(_boot(secret_candidate))
        except Exception as e:
            BOOT["error"] = f"{type(e).__name__}: {e}"

    t = threading.Thread(target=runner, name="rvg-pg-bootstrap", daemon=True)
    t.start()
    t.join(60)
    if BOOT["ok"]:
        logger.info(f"PostgreSQL آماده است ({_safe_host()}) — {BOOT['files_restored']} فایل بازگردانی شد.")
    else:
        logger.error(f"راه‌اندازی اولیه‌ی PostgreSQL ناموفق بود: {BOOT['error'] or 'timeout'}")
    return BOOT


# ── زمان اجرا ────────────────────────────────────────────────────────────────
def is_active() -> bool:
    return _pool is not None and _connected


def status() -> dict:
    return {
        "configured": ENABLED,
        "connected": is_active(),
        "host": _safe_host() if ENABLED else "",
        "worker": WORKER_ID,
        "rev": _last_rev,
        "error": _last_error,
    }


async def _open() -> bool:
    global _pool, _connected, _last_error
    try:
        _pool = await asyncpg.create_pool(
            DATABASE_URL, min_size=1, max_size=max(2, POOL_MAX), timeout=10,
            command_timeout=15, statement_cache_size=0,
            max_inactive_connection_lifetime=300,
            server_settings={"application_name": "rvg-gateway"},
        )
        async with _pool.acquire() as c:
            await _ensure_schema(c)
        _connected = True
        _last_error = ""
        await _start_listener()
        logger.info(f"اتصال PostgreSQL برقرار شد (worker {WORKER_ID}).")
        return True
    except Exception as e:
        _connected = False
        _last_error = f"{type(e).__name__}: {e}"
        logger.warning(f"اتصال به PostgreSQL ناموفق بود: {_last_error}")
        if _pool is not None:
            try:
                await _pool.close()
            except Exception:
                pass
            _pool = None
        return False


def _on_notify(_conn, _pid, _channel, payload):
    try:
        msg = json.loads(payload)
    except Exception:
        return
    if msg.get("by") == WORKER_ID:
        return
    kind = msg.get("t")
    if kind == "state" and int(msg.get("rev") or 0) > _last_rev:
        asyncio.get_running_loop().create_task(_run_state_handler())
    elif kind == "sessions" and _on_sessions is not None:
        try:
            _on_sessions()
        except Exception:
            pass
    elif kind == "file" and msg.get("name"):
        asyncio.get_running_loop().create_task(_pull_file(str(msg["name"])))


async def _start_listener():
    global _listen_conn
    await _close_listener()
    try:
        conn = await _connect_one()
        await conn.add_listener(CHANNEL, _on_notify)
        _listen_conn = conn
    except Exception as e:
        _listen_conn = None
        logger.info(f"LISTEN روی PostgreSQL فعال نشد ({e}) — همگام‌سازی دوره‌ای جایگزین است.")


async def _close_listener():
    global _listen_conn
    if _listen_conn is not None:
        try:
            await _listen_conn.close(timeout=3)
        except Exception:
            pass
    _listen_conn = None


async def _notify(conn, kind: str, **extra):
    payload = json.dumps({"t": kind, "by": WORKER_ID, **extra})
    await conn.execute("SELECT pg_notify($1, $2)", CHANNEL, payload)


async def _run_state_handler():
    global _state_sync_lock
    if _on_state is None:
        return
    if _state_sync_lock is None:
        _state_sync_lock = asyncio.Lock()
    if _state_sync_lock.locked():
        return
    async with _state_sync_lock:
        try:
            await _on_state()
        except Exception as e:
            logger.warning(f"همگام‌سازی state از PostgreSQL ناموفق بود: {e}")


async def _supervisor():
    global _connected, _last_error
    last_cleanup = 0.0
    while True:
        await asyncio.sleep(POLL_SECONDS)
        try:
            if _pool is None:
                if await _open():
                    await _run_state_handler()   # بعد از وصل شدن دیرهنگام: همگام‌سازی کامل
                continue
            rev = await _pool.fetchval("SELECT rev FROM rvg_kv WHERE key = 'state'")
            if not _connected:
                logger.info("اتصال PostgreSQL دوباره برقرار شد.")
            _connected = True
            _last_error = ""
            if rev is not None and int(rev) > _last_rev:
                await _run_state_handler()
            if _listen_conn is None or _listen_conn.is_closed():
                await _start_listener()
            await _sync_files_once()
            if time.time() - last_cleanup > 3600:
                last_cleanup = time.time()
                await _pool.execute("DELETE FROM rvg_sessions WHERE expires_at < $1", time.time())
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if _connected:
                logger.warning(f"اتصال PostgreSQL قطع شد: {e}")
            _connected = False
            _last_error = f"{type(e).__name__}: {e}"


async def start(on_state=None, on_sessions=None) -> bool:
    """on_state: coroutine بدون آرگومان — وقتی state روی دیتابیس توسط worker/نمونه‌ی
    دیگه‌ای عوض شد (یا بعد از وصل شدن دیرهنگام) صدا زده می‌شه.
    on_sessions: تابع معمولی — وقتی سشن‌ها جای دیگه پاک شدن."""
    global _on_state, _on_sessions
    _on_state, _on_sessions = on_state, on_sessions
    if not ENABLED or not _ensure_driver():
        return False
    ok = await _open()
    _tasks.append(asyncio.create_task(_supervisor()))
    return ok


async def stop():
    global _pool, _connected
    for t in _tasks:
        t.cancel()
    _tasks.clear()
    try:
        await _sync_files_once()
    except Exception:
        pass
    await _close_listener()
    if _pool is not None:
        try:
            await asyncio.wait_for(_pool.close(), timeout=5)
        except Exception:
            pass
    _pool = None
    _connected = False


# ── state ────────────────────────────────────────────────────────────────────
async def load_state():
    """برمی‌گردونه: dict یا None (اگه هنوز چیزی ذخیره نشده). روی خطا exception می‌ده."""
    global _last_rev
    row = await _pool.fetchrow("SELECT value::text AS v, rev FROM rvg_kv WHERE key = 'state'")
    if not row:
        return None
    _last_rev = int(row["rev"])
    return json.loads(row["v"])


async def save_state(data: dict) -> int:
    global _last_rev, _last_snapshot
    payload = json.dumps(data, ensure_ascii=False).replace("\\u0000", "")
    async with _pool.acquire() as conn:
        async with conn.transaction():
            rev = int(await conn.fetchval(UPSERT_STATE_SQL, payload, WORKER_ID))
            if time.time() - _last_snapshot > SNAPSHOT_EVERY:
                await conn.execute(
                    "INSERT INTO rvg_state_snapshots (value, rev) VALUES ($1::jsonb, $2)", payload, rev)
                await conn.execute(
                    "DELETE FROM rvg_state_snapshots WHERE id NOT IN "
                    "(SELECT id FROM rvg_state_snapshots ORDER BY id DESC LIMIT $1)", SNAPSHOT_KEEP)
                _last_snapshot = time.time()
            await _notify(conn, "state", rev=rev)
    _last_rev = rev
    return rev


# ── sessions ─────────────────────────────────────────────────────────────────
def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def session_create(token: str, expires_at: float):
    await _pool.execute(
        "INSERT INTO rvg_sessions (token_hash, expires_at) VALUES ($1, $2) "
        "ON CONFLICT (token_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at",
        _th(token), float(expires_at))


async def session_get(token: str):
    """زمان انقضا (float) یا None."""
    val = await _pool.fetchval("SELECT expires_at FROM rvg_sessions WHERE token_hash = $1", _th(token))
    return float(val) if val is not None else None


async def session_delete(token: str):
    async with _pool.acquire() as conn:
        await conn.execute("DELETE FROM rvg_sessions WHERE token_hash = $1", _th(token))
        await _notify(conn, "sessions")


async def sessions_reset(keep_token: str | None, expires_at: float):
    """همه‌ی سشن‌ها رو پاک می‌کنه غیر از keep_token (بعد از تغییر رمز)."""
    async with _pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("DELETE FROM rvg_sessions")
            if keep_token:
                await conn.execute(
                    "INSERT INTO rvg_sessions (token_hash, expires_at) VALUES ($1, $2)",
                    _th(keep_token), float(expires_at))
            await _notify(conn, "sessions")


# ── فایل‌ها ──────────────────────────────────────────────────────────────────
def _sync_names() -> list:
    extra = [n.strip() for n in os.environ.get("RVG_PG_SYNC_FILES", "").split(",") if n.strip()]
    return [n for n in dict.fromkeys([*DEFAULT_SYNC_FILES, *extra]) if _safe_name(n)]


async def _sync_files_once():
    if _data_dir is None or _pool is None:
        return
    for name in _sync_names():
        path = _data_dir / name
        try:
            if path.is_file():
                content = path.read_bytes()
                if len(content) > MAX_SYNC_FILE_BYTES:
                    continue
                digest = hashlib.sha256(content).hexdigest()
                if _file_hashes.get(name) == digest:
                    continue
                async with _pool.acquire() as conn:
                    await conn.execute(
                        "INSERT INTO rvg_files (name, content, sha256) VALUES ($1, $2, $3) "
                        "ON CONFLICT (name) DO UPDATE SET content = EXCLUDED.content, "
                        "sha256 = EXCLUDED.sha256, updated_at = now()",
                        name, content, digest)
                    await _notify(conn, "file", name=name)
                _file_hashes[name] = digest
            elif _file_hashes.get(name):
                async with _pool.acquire() as conn:
                    await conn.execute("DELETE FROM rvg_files WHERE name = $1", name)
                    await _notify(conn, "file", name=name)
                _file_hashes[name] = None
        except Exception as e:
            logger.debug(f"همگام‌سازی فایل {name} ناموفق بود: {e}")


async def _pull_file(name: str):
    if not _safe_name(name) or _pool is None:
        return
    try:
        content = await _pool.fetchval("SELECT content FROM rvg_files WHERE name = $1", name)
        _write_local_file(name, bytes(content) if content is not None else None)
    except Exception as e:
        logger.debug(f"دریافت فایل {name} از PostgreSQL ناموفق بود: {e}")
