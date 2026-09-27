import os

import reflex as rx

# ── علت اصلی رفرش‌های پشت‌سرهم و بیرون افتادن از پنل ─────────────────────────
# Reflex در حالت prod، وقتی Redis خودش (REFLEX_REDIS_URL) ست باشه — که روی
# Reflex Cloud هست — بک‌اند رو با (تعداد CPU × 2 + 1) پروسه‌ی جدا (worker) بالا
# می‌آره. RVG همه‌چیزش (سشن‌ها، لینک‌ها، ترافیک، پروسه‌های MTProto) توی حافظه‌ی
# یک پروسه‌ست؛ پس لاگین روی worker A ثبت می‌شد، درخواست بعدی به worker B می‌رسید
# که سشن رو نمی‌شناخت -> 401 -> ریدایرکت به /login، و هر worker نسخه‌ی state خودش
# رو داشت و روی بقیه ذخیره می‌کرد -> «پنل ریست می‌شه».
# RVG ذاتاً تک‌پروسه‌ایه (main.py هم workers=1 داره)، پس بک‌اند رو روی ۱ worker
# قفل می‌کنیم. (سشن‌ها و state الان روی PostgreSQL هم مشترکن، پس حتی اگه پلتفرم
# چند نمونه بالا بیاره هم دیگه بیرون نمی‌افتید.)
os.environ.setdefault("GRANIAN_WORKERS", "1")   # بک‌اند granian (پیش‌فرض Reflex)
os.environ.setdefault("WEB_CONCURRENCY", "1")   # اگه gunicorn استفاده بشه

# app_name must match the package folder that contains app.py (see the project tree: app/app.py)
config = rx.Config(
    app_name="app",
    telemetry_enabled=False,
)
