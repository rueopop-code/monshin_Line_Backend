require("dotenv").config();
const express = require("express");
const line = require("@line/bot-sdk");
const axios = require("axios");
const path = require("path");
const fs = require("fs");

const app = express();

// ─── LINE SDK Config ───────────────────────────────────────────────────────────
const lineConfig = {
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.LINE_CHANNEL_SECRET,
};
const client = new line.messagingApi.MessagingApiClient(lineConfig);

// ─── JSON body parser (รับ base64 รูปใหญ่ได้) ─────────────────────────────────
// JSON parser เฉพาะ /send-slip เท่านั้น (ไม่ให้ขัดกับ LINE Webhook)

// ─── Serve LIFF HTML + temp images ────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));
app.use("/temp", express.static(path.join(__dirname, "temp")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "liff.html"));
});

// ─── API: รับรูปสลิปจาก LIFF แล้วส่งเข้ากลุ่ม LINE ───────────────────────────
app.post("/send-slip", express.json({ limit: "20mb" }), async (req, res) => {
  try {
    const { base64Image, groupId } = req.body;
    if (!base64Image || !groupId) {
      return res.status(400).json({ success: false, error: "Missing data" });
    }

    // สร้างโฟลเดอร์ temp ถ้ายังไม่มี
    const tempDir = path.join(__dirname, "temp");
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir);

    // บันทึกรูปชั่วคราว
    const filename = `slip_${Date.now()}.jpg`;
    const filepath = path.join(tempDir, filename);
    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    fs.writeFileSync(filepath, Buffer.from(base64Data, "base64"));

    // URL สาธารณะของรูป
    const SERVER_URL = process.env.SERVER_URL || `https://monshin-line-backend.onrender.com`;
    const imageUrl = `${SERVER_URL}/temp/${filename}`;

    // ส่งรูปเข้ากลุ่ม LINE
    await client.pushMessage({
      to: groupId,
      messages: [
        {
          type: "image",
          originalContentUrl: imageUrl,
          previewImageUrl: imageUrl,
        },
      ],
    });

    // ลบไฟล์หลังจาก 60 วินาที
    setTimeout(() => {
      try { fs.unlinkSync(filepath); } catch (e) {}
    }, 60000);

    res.json({ success: true });
  } catch (err) {
    console.error("send-slip error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── LINE Webhook ──────────────────────────────────────────────────────────────
app.post(
  "/webhook",
  line.middleware(lineConfig),
  async (req, res) => {
    res.sendStatus(200);
    const events = req.body.events;
    for (const event of events) {
      await handleEvent(event);
    }
  }
);

// ─── Event Handler ─────────────────────────────────────────────────────────────
async function handleEvent(event) {
  if (event.type !== "message") return;
  if (!["group", "room"].includes(event.source.type)) return;

  const replyToken = event.replyToken;
  const groupId = event.source.groupId || event.source.roomId;

  if (event.message.type === "text") {
    const text = event.message.text.trim().toLowerCase();
    if (text === "ฝากเงิน" || text === "รายงาน" || text === "เปิดฟอร์ม") {
      await client.replyMessage({
        replyToken,
        messages: [buildLiffMessage()],
      });
    }
  }
}

// ─── สร้างข้อความเปิด LIFF ─────────────────────────────────────────────────────
function buildLiffMessage() {
  return {
    type: "template",
    altText: "กดเพื่อเปิดฟอร์มฝากเงิน",
    template: {
      type: "buttons",
      title: "รายงานฝากเงินประจำวัน",
      text: "กดปุ่มด้านล่างเพื่อกรอกรายละเอียดและแนบสลิป",
      actions: [
        {
          type: "uri",
          label: "📋 เปิดฟอร์มฝากเงิน",
          uri: `https://liff.line.me/${process.env.LIFF_ID}`,
        },
      ],
    },
  };
}

// ─── Start Server ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
