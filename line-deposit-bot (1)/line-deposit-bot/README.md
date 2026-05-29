# 📋 LINE Deposit Bot — คู่มือติดตั้ง

ระบบรายงานฝากเงินประจำวันผ่าน LINE กลุ่ม

---

## สิ่งที่ต้องเตรียม

- บัญชี LINE ปกติ (สมัครฟรี)
- บัญชี GitHub (สมัครฟรี) → github.com
- บัญชี Railway (สมัครฟรี) → railway.app
- API Key จาก Thunder Solution → developer.thunder.in.th

---

## ขั้นตอนที่ 1 — สร้าง LINE Bot

1. ไปที่ https://developers.line.biz แล้วล็อกอิน
2. กด "Create a Provider" → ตั้งชื่อร้านค้า
3. กด "Create a channel" → เลือก "Messaging API"
4. กรอกข้อมูล:
   - Channel name: ชื่อ Bot (เช่น "บอทร้านค้า")
   - Category: เลือกหมวดที่ใกล้เคียง
5. หลังสร้าง → ไปที่ tab "Messaging API"
   - เปิด "Allow bot to join group chats" ✅
   - คัดลอก Channel Access Token (กด Issue ก่อน)
   - คัดลอก Channel Secret (อยู่ใน tab Basic settings)

---

## ขั้นตอนที่ 2 — สร้าง LIFF App

1. ใน LINE Developers → เลือก Channel ที่สร้างไว้
2. ไปที่ tab "LIFF" → กด "Add"
3. ตั้งค่า:
   - LIFF app name: "ฟอร์มฝากเงิน"
   - Size: Full
   - Endpoint URL: https://yourapp.railway.app (จะได้ URL จาก Railway ใน Step 3)
   - Scopes: เลือก "chat_message.write" ✅
4. กด "Add" → คัดลอก LIFF ID

---

## ขั้นตอนที่ 3 — Deploy บน Railway

1. ไปที่ https://railway.app → Sign in with GitHub
2. กด "New Project" → "Deploy from GitHub repo"
3. Upload โค้ดโปรเจกต์นี้ขึ้น GitHub ก่อน แล้วเลือก repo
4. ใน Railway → ไปที่ "Variables" → เพิ่ม:

   ```
   LINE_CHANNEL_ACCESS_TOKEN = (จาก Step 1)
   LINE_CHANNEL_SECRET       = (จาก Step 1)
   LIFF_ID                   = (จาก Step 2)
   THUNDER_API_KEY           = (จาก developer.thunder.in.th)
   ```

5. Railway จะ Deploy อัตโนมัติ → คัดลอก URL ที่ได้ (เช่น https://xxx.railway.app)

---

## ขั้นตอนที่ 4 — ตั้งค่า Webhook

1. กลับไป LINE Developers → tab "Messaging API"
2. ใส่ Webhook URL: `https://xxx.railway.app/webhook`
3. กด "Verify" → ต้องขึ้น "Success"
4. เปิด "Use webhook" ✅

---

## ขั้นตอนที่ 5 — แก้ไขโค้ด LIFF

เปิดไฟล์ `public/liff.html` บรรทัดที่ 170:
```js
const LIFF_ID = "YOUR_LIFF_ID"; // ← เปลี่ยนเป็น LIFF ID จริง
```

---

## ขั้นตอนที่ 6 — เพิ่ม Bot เข้ากลุ่ม LINE

1. เปิดกลุ่ม LINE ที่ต้องการ
2. กด "เพิ่มเพื่อน" → ค้นหา Bot ด้วย QR Code จาก LINE Developers
3. ทดสอบพิมพ์ "ฝากเงิน" ในกลุ่ม → Bot จะส่งปุ่มเปิดฟอร์ม

---

## คำสั่งที่ Bot รับรู้

| พิมพ์ในกลุ่ม | Bot จะทำ |
|------------|---------|
| `ฝากเงิน`  | ส่งปุ่มเปิดฟอร์ม LIFF |
| `รายงาน`   | ส่งปุ่มเปิดฟอร์ม LIFF |
| `เปิดฟอร์ม` | ส่งปุ่มเปิดฟอร์ม LIFF |
| ส่งรูปสลิป | ตรวจสอบสลิปผ่าน Thunder API |

---

## โครงสร้างโปรเจกต์

```
line-deposit-bot/
├── index.js          ← Server + LINE Webhook
├── public/
│   └── liff.html     ← ฟอร์ม LIFF (เปิดในแอป LINE)
├── package.json
├── .env.example      ← ตัวอย่าง Environment Variables
└── README.md
```

---

## ติดปัญหา?

- **Webhook Verify ไม่ผ่าน** → ตรวจสอบว่า Server รันอยู่และ URL ถูกต้อง
- **LIFF เปิดไม่ได้** → ตรวจสอบ LIFF ID ในไฟล์ liff.html
- **ส่งข้อความไม่ได้** → ต้องเปิด "chat_message.write" scope ใน LIFF settings
