# Club Connect v0.8

هسته‌ی پروکسی بدون نیاز به تنظیم. یک پورت واحد، هم **SOCKS5** (با UDP) و هم **HTTP proxy**.
پیش‌فرض: `127.0.0.1:8888`

    ./clubconnect                 # بدون هیچ کانفیگی
    ./clubconnect -port 8080 -order warp,psiphon
    ./clubconnect -mode psiphon   # فقط یک هسته

## هسته‌ها (هیچ‌کدام کانفیگ دستی نمی‌خواهند)
- **warp**: حساب رایگان خودکار، WireGuard داخل برنامه (بدون root)، پیدا کردن endpoint به‌صورت موازی، آخرین endpoint سالم ذخیره می‌شود، UDP پشتیبانی می‌شود
- **psiphon**: کانفیگ را خود Club Connect می‌سازد (فقط باینری `psiphon-tunnel-core` کنار برنامه باشد)
- **tor**: بریج‌های پیش‌فرض داخل برنامه است (باینری `tor` و `lyrebird`/`snowflake-client` کنار برنامه)

هسته‌ی سالم و سریع‌تر خودکار انتخاب می‌شود؛ اگر یکی قطع شود، به بعدی می‌رود.

## API کنترل (فقط 127.0.0.1، پورت 8808)
    GET /status
    GET /switch?backend=auto|warp|psiphon|tor
اگر `api_token` ست باشد، هدر `X-Token` لازم است.

پورت‌های پیش‌فرض همه با ۸: پروکسی **8888**، API **8808**، و هسته‌های داخلی (Psiphon/Tor) از **8801–8899**.

## امنیت
پیش‌فرض فقط روی loopback گوش می‌دهد. اگر `listen` غیر از 127.0.0.1 باشد، `username/password` اجباری است.

## بیلد
Actions → Build Club Connect → Run workflow (یا tag مثل `v0.8`).

## پلتفرم‌ها (۹ خروجی)
android-arm64, android-armv7a, linux-amd64, linux-arm64, windows-amd64, windows-x86, windows-arm64, macos-arm64, macos-amd64

- macOS: بعد از استخراج یک‌بار `xattr -d com.apple.quarantine clubconnect psiphon-tunnel-core` بزنید
- `tor` در linux-arm64 و windows-arm64 همراه zip نیست؛ باینری tor را خودتان کنار برنامه بگذارید
- iOS پشتیبانی نمی‌شود (اپ‌های iOS نمی‌توانند باینری جدا اجرا کنند)
