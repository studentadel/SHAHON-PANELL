# ⚡ ISSPanel v2.0 – Redesign

پنل حرفه‌ای مدیریت کانفیگ‌های VLESS با طراحی مدرن آبی تیره

## ویژگی‌های نسخه جدید

- ✅ طراحی کاملاً جدید (تم آبی تیره + لوگو)
- ✅ افزودن / ویرایش / حذف کامل برای:
  - پنل‌ها
  - اینباندها
  - کاربران
- ✅ پشتیبانی از چند پنل (Local + Remote)
- ✅ تخصیص اینباند به کاربر
- ✅ پریست ضد فیلتر (ws + grpc + xhttp)
- ✅ گزینه‌های بیشتر پروتکل و Fingerprint
- ✅ Subscription لینک (`/sub/:token` و `/sub64/:token`)

### پروتکل‌های پشتیبانی شده
`ws` · `grpc` · `xhttp` · `tcp` · `http` · `h2`

### Fingerprint ها
`chrome` · `firefox` · `safari` · `ios` · `android` · `edge` · `360` · `qq` · `random` · `randomized` · `none`

### TLS / ALPN
- TLS: `tls` · `none` · `reality`
- ALPN: `http/1.1` · `h2` · `h3` · `none`

## نصب و اجرا

```bash
# کپی فایل محیط
cp .env.example .env

# نصب وابستگی‌ها
npm install

# اجرا
npm start
```

سپس به آدرس `http://localhost:3000` بروید.

### متغیرهای مهم `.env`

| متغیر | توضیح |
|-------|-------|
| `ADMIN_USER` | نام کاربری ادمین |
| `ADMIN_PASS` | رمز عبور ادمین |
| `AGENT_KEY` | کلید ارتباط بین پنل‌ها |
| `NODE_ROLE` | `master` / `agent` / `hybrid` |
| `XRAY_BASE_PORT` | پورت پایه Xray |

## ساختار

```
ISSpadel-redesign/
├── public/
│   ├── index.html
│   ├── login.html
│   └── dashboard.html
├── server.js
├── package.json
├── .env.example
└── README.md
```

---

نسخه بازطراحی شده برای استفاده آسان‌تر و حرفه‌ای‌تر.
