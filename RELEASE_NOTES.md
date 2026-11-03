# Club Connect v0.8.1

هسته‌ی پروکسی بدون نیاز به تنظیم. یک پورت واحد، هم **SOCKS5** (با UDP) و هم **HTTP proxy**.
آدرس پیش‌فرض: `127.0.0.1:1819`

> این برنامه یک **پروکسی** است، نه VPN سراسری. باید برنامه یا سیستم‌ات را روی آدرس بالا تنظیم کنی.

## تازه در v0.8.1

- **Tor هم داخل هسته embed شد.** دیگر لازم نیست `tor` را جدا کنار برنامه بگذاری (در بیلد ریلیز).
- **سایفون، Aether، lyrebird و snowflake-client** مثل قبل داخل یک فایل هستند.
- ترتیب جست‌وجوی `tor` اصلاح شد: اول کپی extractشده از داخل برنامه، بعد بقیه.
- پیام خطای Preflight برای Tor شفاف‌تر شد.
- بیلد: Tor expert bundle قبل از `go build` داخل `internal/bundle/bin` کپی می‌شود تا واقعاً embed شود (قبلاً فقط کنار zip می‌آمد).
- Go نسخهٔ بیلد روی 1.22.x قفل شد.

## یک فایل = هسته کامل

در ریلیز رسمی، داخل `clubconnect` این‌ها embed شده‌اند:

| برنامه | نقش |
|---|---|
| aether | MASQUE / gool / mim / noize و بقیه variantهای پیشرفته WARP |
| psiphon-tunnel-core | سایفون |
| tor | تور |
| lyrebird | پل‌های obfs4 / meek / webtunnel |
| snowflake-client | پل Snowflake |

موقع اجرا در `<data_dir>/bin` باز می‌شوند. نیازی به دانلود جداگانه نیست.

**استثنا:** روی `linux-arm64` و `windows-arm64` ممکن است tor یا aether در ریلیز upstream موجود نباشد؛ آن پلتفرم‌ها فقط حالت‌های موجود را نشان می‌دهند.

## حالت‌ها

| کلید | حالت |
|---|---|
| 1 | Auto |
| 2 | WARP |
| 3 | Psiphon |
| 4 | Tor |
| 5 | WARP → Psiphon |
| 6 | WARP → Tor |

## شروع سریع

1. zip ریلیز را باز کن و `clubconnect` / `clubconnect.exe` را اجرا کن.
2. از منو حالت را انتخاب کن (مثلاً `1` برای Auto).
3. وقتی healthy شد، برنامه‌ات را روی `127.0.0.1:1819` (SOCKS5 یا HTTP) بگذار.
4. توقف: `S` یا `Q`.

## API (فقط 127.0.0.1:8808)

```
GET /status
GET /start?mode=auto[&variant=masque-h2]
GET /variants
GET /stop
GET /switch?backend=...
GET /test
```

## رفع‌شده نسبت به v0.8

- Tor دیگر «فایل جدا» نیست؛ داخل هسته است.
- پیام‌های کمبود باینری شفاف‌تر شدند.
- بیلد workflow طوری اصلاح شد که tor قبل از compile داخل باینری برود.

## بیلد از سورس

بدون محتوای `internal/bundle/bin` هم `go build` کار می‌کند (فقط WireGuard داخلی + جست‌وجوی باینری‌های خارجی).
برای ریلیز کامل از Actions استفاده کن تا aether / psiphon / tor / lyrebird / snowflake embed شوند.
