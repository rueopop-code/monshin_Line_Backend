require("dotenv").config();
const express = require("express");
const line = require("@line/bot-sdk");
const axios = require("axios");
const path = require("path");

const app = express();

// ─── LINE SDK Config ───────────────────────────────────────────────────────────
const lineConfig = {
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.LINE_CHANNEL_SECRET,
};
const client = new line.messagingApi.MessagingApiClient(lineConfig);

// ─── Serve LIFF HTML ───────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "liff.html"));
});

// ─── LINE Webhook ──────────────────────────────────────────────────────────────
// ต้องใช้ raw body สำหรับ verify signature
app.post(
  "/webhook",
  line.middleware(lineConfig),
  async (req, res) => {
    res.sendStatus(200); // ตอบ LINE ก่อนเสมอ
    const events = req.body.events;
    for (const event of events) {
      await handleEvent(event);
    }
  }
);

// ─── Event Handler ─────────────────────────────────────────────────────────────
async function handleEvent(event) {
  // รับเฉพาะ message event ในกลุ่มหรือห้อง
  if (event.type !== "message") return;
  if (!["group", "room"].includes(event.source.type)) return;

  const replyToken = event.replyToken;
  const groupId = event.source.groupId || event.source.roomId;

  // ─── กรณีส่งรูป: ตรวจสอบสลิปผ่าน Thunder API ───
  if (event.message.type === "image") {
    await handleSlipImage(replyToken, event.message.id, groupId);
    return;
  }

  // ─── กรณีส่งข้อความ: เปิดฟอร์ม LIFF ───
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

// ─── ตรวจสอบสลิปกับ Thunder API ───────────────────────────────────────────────
async function handleSlipImage(replyToken, messageId, groupId) {
  try {
    // ดึงรูปจาก LINE
    const stream = await client.getMessageContent(messageId);
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    const imageBuffer = Buffer.concat(chunks);
    const base64Image = imageBuffer.toString("base64");

    // ส่งไป Thunder API
    const response = await axios.post(
      "https://api.thunder.in.th/v2/verify/bank",
      { image: base64Image },
      {
        headers: {
          Authorization: `Bearer ${process.env.THUNDER_API_KEY}`,
          "Content-Type": "application/json",
        },
      }
    );

    const data = response.data;

    if (data.success) {
      const d = data.data;
      const amount = d.amount?.amount || 0;
      const senderName = d.sender?.account?.name?.th || "—";
      const senderBank = d.sender?.bank?.short || "—";
      const receiverName = d.receiver?.account?.name?.th || "—";
      const receiverBank = d.receiver?.bank?.short || "—";
      const transRef = d.transRef || "—";

      await client.replyMessage({
        replyToken,
        messages: [
          {
            type: "text",
            text:
              `✅ ตรวจสอบสลิปสำเร็จ\n` +
              `────────────────────\n` +
              `💰 จำนวน : ${amount.toLocaleString("th-TH", { minimumFractionDigits: 2 })} บาท\n` +
              `👤 โอนจาก : ${senderName} (${senderBank})\n` +
              `🏦 เข้าบัญชี : ${receiverName} (${receiverBank})\n` +
              `🔖 อ้างอิง : ${transRef}\n` +
              `────────────────────\n` +
              `✔️ บันทึกเรียบร้อยแล้ว`,
          },
        ],
      });
    } else {
      await client.replyMessage({
        replyToken,
        messages: [
          {
            type: "text",
            text: "⚠️ ตรวจสอบสลิปไม่สำเร็จ\nกรุณาลองใหม่อีกครั้ง หรือส่งสลิปที่ชัดเจนกว่านี้",
          },
        ],
      });
    }
  } catch (err) {
    console.error("Thunder API error:", err.message);
    await client.replyMessage({
      replyToken,
      messages: [
        {
          type: "text",
          text: "❌ เกิดข้อผิดพลาดในการตรวจสอบสลิป\nกรุณาติดต่อแอดมิน",
        },
      ],
    });
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
