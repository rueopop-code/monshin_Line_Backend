require("dotenv").config();
const express = require("express");
const line = require("@line/bot-sdk");
const path = require("path");
const fs = require("fs");

const app = express();

const lineConfig = {
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.LINE_CHANNEL_SECRET,
};
const client = new line.messagingApi.MessagingApiClient(lineConfig);

// Serve static files
app.use(express.static(path.join(__dirname, "public")));
app.use("/temp", express.static(path.join(__dirname, "temp")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "liff.html"));
});

// รับสลิปจาก LIFF แล้ว push รูปเข้ากลุ่ม
app.post("/send-slip", express.json({ limit: "20mb" }), async (req, res) => {
  try {
    const { base64Image, groupId } = req.body;
    if (!base64Image || !groupId) {
      return res.status(400).json({ success: false, error: "Missing data" });
    }

    const tempDir = path.join(__dirname, "temp");
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

    const filename = "slip_" + Date.now() + ".jpg";
    const filepath = path.join(tempDir, filename);
    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    fs.writeFileSync(filepath, Buffer.from(base64Data, "base64"));

    const SERVER_URL = process.env.SERVER_URL || "https://monshin-line-backend.onrender.com";
    const imageUrl = SERVER_URL + "/temp/" + filename;

    await client.pushMessage({
      to: groupId,
      messages: [{
        type: "image",
        originalContentUrl: imageUrl,
        previewImageUrl: imageUrl,
      }],
    });

    setTimeout(function() {
      try { fs.unlinkSync(filepath); } catch(e) {}
    }, 60000);

    res.json({ success: true });
  } catch (err) {
    console.error("send-slip error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// LINE Webhook
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

async function handleEvent(event) {
  if (event.type !== "message") return;
  if (!["group", "room"].includes(event.source.type)) return;

  const replyToken = event.replyToken;

  if (event.message.type === "text") {
    const text = event.message.text.trim();
    if (text === "ฝากเงิน" || text === "รายงาน" || text === "เปิดฟอร์ม") {
      await client.replyMessage({
        replyToken,
        messages: [buildLiffMessage()],
      });
    }
  }
}

function buildLiffMessage() {
  return {
    type: "template",
    altText: "กดเพื่อเปิดฟอร์มฝากเงิน",
    template: {
      type: "buttons",
      title: "รายงานฝากเงินประจำวัน",
      text: "กดปุ่มด้านล่างเพื่อกรอกรายละเอียดและแนบสลิป",
      actions: [{
        type: "uri",
        label: "เปิดฟอร์มฝากเงิน",
        uri: "https://liff.line.me/" + process.env.LIFF_ID,
      }],
    },
  };
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log("Server running on port " + PORT);
});
