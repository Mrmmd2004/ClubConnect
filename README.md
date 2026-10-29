# Club Connect v0.9

هسته‌ی پروکسی بدون نیاز به تنظیم. یک پورت واحد، هم **SOCKS5** (با UDP) و هم **HTTP proxy**.
پیش‌فرض: `127.0.0.1:8888`

## تغییر مهم v0.9: دیگر خودکار شروع نمی‌شود
با باز کردن برنامه **هیچ هسته‌ای اجرا نمی‌شود**؛ یک منو می‌آید و خودتان حالت را انتخاب می‌کنید.

    clubconnect.exe                 # منو
    clubconnect.exe -mode warp      # بدون منو، همان حالت را بلافاصله شروع کن
    clubconnect.exe -mode warp+tor -menu   # شروع کن و منو هم نشان بده

## حالت‌ها
| حالت | معنی |
|---|---|
| `auto` | بهترین هسته‌ی سالم (WARP / Psiphon / Tor) را خودش انتخاب و در صورت قطعی عوض می‌کند |
| `warp` | فقط Cloudflare WARP |
| `psiphon` | فقط Psiphon |
| `tor` | فقط Tor |
| `warp+psiphon` | **Cloudflare ← Psiphon**: Psiphon همه‌ی اتصال‌هایش را از داخل تونل WARP می‌زند |
| `warp+tor` | **Cloudflare ← Tor**: Tor از داخل تونل WARP به ریلی/بریج وصل می‌شود |

در حالت‌های زنجیره‌ای فقط پروتکل‌های TCP استفاده می‌شوند (QUIC و Snowflake از یک hop سوکس رد نمی‌شوند).

## تنظیمات منو (۹)
پورت پروکسی، ریجن Psiphon، سبک پروتکل Psiphon (`auto` / `cdn` / `direct`)، مسیر `psiphon-tunnel-core`،
نوع بریج Tor (`auto` / `obfs4` / `snowflake` / `meek` / `webtunnel` / `none`)، مسیر `tor`، فایل بریج دلخواه،
endpoint دلخواه WARP، ثبت دستگاه جدید WARP، لاگ کامل (`Verbose`). همه در `settings.json` کنار داده‌ها ذخیره می‌شوند.

- اگر Tor Browser نصب باشد (Desktop / Downloads / Program Files)، `tor` و `lyrebird` و `snowflake-client` آن خودکار پیدا می‌شوند.
- گزینه‌ی ۷ منو (**Test connection**) یک درخواست واقعی از داخل پروکسی می‌زند و IP خروجی را نشان می‌دهد
  (`warp=on` یعنی ترافیک از Cloudflare خارج می‌شود).

## API کنترل (فقط 127.0.0.1، پورت 8808)
    GET /status
    GET /start?mode=auto|warp|psiphon|tor|warp+psiphon|warp+tor
    GET /stop
    GET /switch?backend=...        (داخل حالت در حال اجرا)
    GET /test
اگر `api_token` ست باشد، هدر `X-Token` لازم است. بدون `-mode` و بدون ترمینال (مثلاً وقتی برنامه‌ی دیگری آن را اجرا می‌کند)
هسته بیکار می‌ماند تا `/start` صدا زده شود.

## هسته‌ها
- **warp**: حساب رایگان خودکار، WireGuard داخل برنامه (بدون root)، endpoint موازی، UDP، DNS با اولویت IPv4 و کش
- **psiphon**: کانفیگ را خود برنامه می‌سازد. بایننری باید از fork مورد استفاده‌ی Aether ساخته شود (CI همین کار را می‌کند)؛
  اگر Psiphon در لحظه‌ی شروع بسته شود، دلیلش در لاگ چاپ می‌شود و با لیست ساده‌تر پروتکل‌ها دوباره تلاش می‌کند
- **tor**: بریج‌های پیش‌فرض داخل برنامه است؛ `tor` و `lyrebird`/`snowflake-client` کنار برنامه یا در Tor Browser

پورت‌ها: پروکسی **8888**، API **8808**، هسته‌های داخلی از **8801–8899**.

## امنیت
پیش‌فرض فقط روی loopback گوش می‌دهد. اگر `listen` غیر از 127.0.0.1 باشد، `username/password` اجباری است.

## بیلد
Actions → Build Club Connect → Run workflow (یا tag مثل `v0.9`).

## پلتفرم‌ها (۹ خروجی)
android-arm64, android-armv7a, linux-amd64, linux-arm64, windows-amd64, windows-x86, windows-arm64, macos-arm64, macos-amd64

- macOS: بعد از استخراج یک‌بار `xattr -d com.apple.quarantine clubconnect psiphon-tunnel-core` بزنید
- `tor` در linux-arm64 و windows-arm64 همراه zip نیست
- iOS پشتیبانی نمی‌شود
