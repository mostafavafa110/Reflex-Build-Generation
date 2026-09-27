"""RVG Gateway — Reflex entrypoint  (project layout: app/app.py, app_name="app").

The original RVG code (FastAPI app, VLESS/Trojan/Shadowsocks/MTProto relays,
HTML dashboard) lives UNMODIFIED in app/rvg/. This file only:

  1. makes app/rvg importable and picks a writable data directory,
  2. hands RVG's FastAPI instance to Reflex through `api_transformer`
     (https://reflex.dev/docs/api-routes/overview/) so every RVG route
     (/login, /dashboard, /api/*, /ws/{uuid}, /sub/*, ...) is served by the
     same backend that serves Reflex's own /_event, /ping and /_upload,
  3. runs RVG's startup/shutdown through a Reflex lifespan task
     (https://reflex.dev/docs/utility-methods/lifespan-tasks/),
  4. exposes a small native-Reflex landing page ("/") with live stats and a
     button that opens the RVG panel.
"""
import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import reflex as rx

logger = logging.getLogger("RVG-Reflex")

ROOT = Path(__file__).resolve().parent.parent
RVG_DIR = Path(__file__).resolve().parent / "rvg"


# ── 1. environment ───────────────────────────────────────────────────────────
def _pick_data_dir() -> str:
    """RVG persists its state to DATA_DIR (default /data, which is usually not
    writable on Reflex Cloud). Use the first writable candidate. Local disk is
    NOT persistent across restarts there -> set DATABASE_URL (PostgreSQL); the
    local folder is then only a cache/backup."""
    for cand in (os.environ.get("DATA_DIR"), "/data", str(ROOT / ".rvg_data"), "/tmp/rvg_data"):
        if not cand:
            continue
        try:
            p = Path(cand)
            p.mkdir(parents=True, exist_ok=True)
            probe = p / ".write_test"
            probe.write_text("ok")
            probe.unlink()
            return str(p)
        except Exception:
            continue
    return "/tmp"


os.environ["DATA_DIR"] = _pick_data_dir()

# RVG modules import each other with top-level names (central, pages, protocol.*,
# `from main import ...`), so its folder must be first on sys.path.
if str(RVG_DIR) not in sys.path:
    sys.path.insert(0, str(RVG_DIR))

# ── 2. load RVG (import errors are shown on the landing page, not swallowed) ──
rvg_main = None
_RVG_ERROR = ""
try:
    import main as rvg_main  # app/rvg/main.py
except Exception as exc:  # pragma: no cover
    logger.exception("RVG failed to import")
    _RVG_ERROR = f"{type(exc).__name__}: {exc}"

# ── 3. start/stop exactly once, whichever hook fires first ───────────────────
_state = {"started": False, "stopped": False}
_lock = asyncio.Lock()

if rvg_main is not None:
    _orig_startup = rvg_main.startup
    _orig_shutdown = rvg_main.shutdown

    async def _startup_once():
        async with _lock:
            if _state["started"]:
                return
            _state["started"] = True  # set first: never retry a failing startup per-request
            try:
                await _orig_startup()
            except Exception:
                logger.exception("RVG startup failed")

    async def _shutdown_once():
        if _state["stopped"] or not _state["started"]:
            return
        _state["stopped"] = True
        try:
            await _orig_shutdown()
        except Exception:
            logger.exception("RVG shutdown failed")

    # RVG registered its handlers with @app.on_event(...): swap them for the
    # idempotent versions so they cannot run twice next to the Reflex lifespan.
    _router = rvg_main.app.router
    for _lst, _old, _new in (
        (getattr(_router, "on_startup", None), _orig_startup, _startup_once),
        (getattr(_router, "on_shutdown", None), _orig_shutdown, _shutdown_once),
    ):
        if isinstance(_lst, list):
            _lst[:] = [_new if f is _old else f for f in _lst]

    # Safety net: if no lifespan hook ran, start RVG on the first HTTP request.
    @rvg_main.app.middleware("http")
    async def _lazy_start(request, call_next):
        if not _state["started"]:
            await _startup_once()
        return await call_next(request)

    @asynccontextmanager
    async def _rvg_lifespan():
        await _startup_once()
        try:
            yield
        finally:
            await _shutdown_once()


# ── 4. native Reflex landing page ────────────────────────────────────────────
def _backend_base() -> str:
    """'' = same origin (normal case). If Reflex's api_url points to a real
    backend host, use it so the panel link always reaches the backend."""
    try:
        from reflex.config import get_config

        url = (get_config().api_url or "").rstrip("/")
    except Exception:
        url = ""
    return "" if (not url or "localhost" in url or "127.0.0.1" in url) else url


PANEL_URL = f"{_backend_base()}/login"


class PanelState(rx.State):
    ready: bool = False
    error: str = _RVG_ERROR
    uptime: str = "--:--:--"
    connections: int = 0
    links_total: int = 0
    links_active: int = 0
    traffic: str = "0 B"
    storage: str = "file"

    @rx.event
    def refresh(self):
        m = rvg_main
        if m is None:
            return
        try:
            links = dict(m.LINKS)
            self.uptime = m.uptime()
            self.connections = len(m.connections)
            self.links_total = len(links)
            self.links_active = sum(1 for link in links.values() if m.is_link_allowed(link))
            self.traffic = m.fmt_bytes(int(m.stats["total_bytes"]))
            if getattr(m, "pgstore", None) is not None and m.pgstore.is_active():
                self.storage = "postgres"
            elif m.REDIS_CONNECTED:
                self.storage = "redis"
            else:
                self.storage = "file"
            self.error = ""
            self.ready = True
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"


def stat_card(label: str, value) -> rx.Component:
    return rx.card(
        rx.vstack(
            rx.text(label, size="2", color_scheme="gray"),
            rx.heading(value, size="6"),
            align="center",
            spacing="1",
        ),
        width="100%",
    )


def index() -> rx.Component:
    return rx.el.div(
        rx.container(
            rx.vstack(
                rx.image(src="/placeholder.svg", width="72px", height="72px", alt="RVG"),
                rx.heading("RVG Gateway", size="9"),
                rx.text(
                    "پنل مدیریت پروکسی چندپروتکلی — VLESS · Trojan · Shadowsocks · MTProto",
                    color_scheme="gray",
                    size="4",
                    text_align="center",
                ),
                rx.cond(
                    PanelState.error != "",
                    rx.callout(PanelState.error, icon="triangle_alert", color_scheme="red", width="100%"),
                ),
                rx.grid(
                    stat_card("زمان فعالیت", PanelState.uptime),
                    stat_card("اتصال‌های زنده", PanelState.connections),
                    stat_card("لینک‌های فعال", PanelState.links_active),
                    stat_card("کل لینک‌ها", PanelState.links_total),
                    stat_card("ترافیک کل", PanelState.traffic),
                    stat_card("ذخیره‌سازی", PanelState.storage),
                    columns="2",
                    spacing="3",
                    width="100%",
                ),
                rx.hstack(
                    # full page load on purpose: /login is a backend (FastAPI) route, not a Next.js page
                    rx.button(
                        "ورود به پنل مدیریت",
                        size="3",
                        on_click=rx.call_script(f"window.location.href='{PANEL_URL}'"),
                    ),
                    rx.button("بروزرسانی آمار", size="3", variant="soft", on_click=PanelState.refresh),
                    spacing="3",
                    wrap="wrap",
                    justify="center",
                ),
                spacing="5",
                align="center",
                padding_y="4em",
            ),
            size="3",
        ),
        dir="rtl",
    )


app = rx.App(
    theme=rx.theme(appearance="dark", accent_color="teal", radius="large"),
    api_transformer=rvg_main.app if rvg_main is not None else None,
)
app.add_page(index, route="/", title="RVG Gateway", on_load=PanelState.refresh)

if rvg_main is not None:
    app.register_lifespan_task(_rvg_lifespan)
