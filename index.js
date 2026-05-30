require("dotenv").config();
const express = require("express");
const line = require("@line/bot-sdk");
const path = require("path");

const app = express();

const lineConfig = {
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.LINE_CHANNEL_SECRET,
};
const client = new line.messagingApi.MessagingApiClient(lineConfig);

const SUPABASE_URL = process.env.SUPABASE_URL || "https://mnilcsbyhtmauvuadrjs.supabase.co";
const SUPABASE_KEY = process.env.SUPABASE_KEY;

// ─── Supabase Helper ───────────────────────────────────────────────────────────
async function supabase(path, method = "GET", body = null) {
  const fetch = (await import("node-fetch")).default;
  const opts = {
    method,
    headers: {
      "Content-Type": "application/json",
      "apikey": SUPABASE_KEY,
      "Authorization": "Bearer " + SUPABASE_KEY,
      "Prefer": method === "POST" ? "return=minimal" : ""
    }
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(SUPABASE_URL + "/rest/v1" + path, opts);
  if (res.status === 204 || res.status === 201) return null;
  return res.json();
}

// ─── บันทึกรายงานลง Supabase ──────────────────────────────────────────────────
app.post("/save-report", express.json({ limit: "1mb" }), async (req, res) => {
  try {
    const data = req.body;
    await supabase("/reports", "POST", data);
    res.json({ success: true });
  } catch (err) {
    console.error("save-report error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── รับ URL รูปจาก Cloudinary แล้ว push เข้ากลุ่ม LINE ──────────────────────
app.post("/send-slip", express.json({ limit: "1mb" }), async (req, res) => {
  try {
    const { imageUrl, groupId } = req.body;
    if (!imageUrl || !groupId) return res.status(400).json({ success: false });
    await client.pushMessage({
      to: groupId,
      messages: [{ type: "image", originalContentUrl: imageUrl, previewImageUrl: imageUrl }]
    });
    res.json({ success: true });
  } catch (err) {
    console.error("send-slip error:", err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── LINE Webhook ──────────────────────────────────────────────────────────────
app.post("/webhook", line.middleware(lineConfig), async (req, res) => {
  res.sendStatus(200);
  for (const event of req.body.events) {
    await handleEvent(event);
  }
});

async function handleEvent(event) {
  if (event.type !== "message") return;
  if (!["group", "room"].includes(event.source.type)) return;

  const replyToken = event.replyToken;
  const groupId = event.source.groupId || event.source.roomId;

  if (event.message.type === "text") {
    const text = event.message.text.trim();

    if (["ฝากเงิน", "รายงาน", "เปิดฟอร์ม"].includes(text)) {
      await client.replyMessage({ replyToken, messages: [buildLiffMessage()] });

    } else if (text === "เมนู" || text === "menu") {
      await client.replyMessage({ replyToken, messages: [buildMenuMessage()] });

    } else if (text === "ยอดวันนี้") {
      const msg = await getTodayReport(groupId);
      await client.replyMessage({ replyToken, messages: [msg] });

    } else if (text === "ยอดเดือนนี้") {
      const msg = await getMonthReport(groupId);
      await client.replyMessage({ replyToken, messages: [msg] });

    } else if (text === "สรุปยอด") {
      await client.replyMessage({ replyToken, messages: [buildSummaryMenu()] });

    } else if (text.startsWith("เดือน:")) {
      const monthStr = text.replace("เดือน:", "").trim();
      const msg = await getMonthReportByName(groupId, monthStr);
      await client.replyMessage({ replyToken, messages: [msg] });
    }
  }
}

// ─── ดึงยอดวันนี้ ──────────────────────────────────────────────────────────────
async function getTodayReport(groupId) {
  try {
    const today = new Date().toISOString().split("T")[0];
    const data = await supabase(
      `/reports?report_date=eq.${today}&group_id=eq.${groupId}&order=created_at.desc&limit=1`
    );
    if (!data || data.length === 0) {
      return { type: "text", text: "📊 ยังไม่มีรายงานวันนี้ครับ\nพิมพ์ \"ฝากเงิน\" เพื่อเปิดฟอร์ม" };
    }
    const r = data[0];
    return buildReportFlex("📊 ยอดวันนี้", formatThaiDate(r.report_date), r);
  } catch (err) {
    return { type: "text", text: "❌ ดึงข้อมูลไม่ได้ครับ: " + err.message };
  }
}

// ─── ดึงยอดเดือนนี้ ────────────────────────────────────────────────────────────
async function getMonthReport(groupId) {
  try {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, "0");
    const from = `${year}-${month}-01`;
    const to = `${year}-${month}-31`;
    const data = await supabase(
      `/reports?report_date=gte.${from}&report_date=lte.${to}&group_id=eq.${groupId}`
    );
    if (!data || data.length === 0) {
      return { type: "text", text: "📅 ยังไม่มีรายงานเดือนนี้ครับ" };
    }
    return buildMonthFlex(data, thaiMonths[now.getMonth()] + " " + (year + 543));
  } catch (err) {
    return { type: "text", text: "❌ ดึงข้อมูลไม่ได้ครับ: " + err.message };
  }
}

// ─── ดึงยอดตามเดือนที่เลือก ────────────────────────────────────────────────────
async function getMonthReportByName(groupId, monthName) {
  try {
    const now = new Date();
    const year = now.getFullYear();
    const monthIdx = thaiMonths.indexOf(monthName);
    if (monthIdx === -1) return { type: "text", text: "❌ ไม่พบเดือน: " + monthName };
    const month = String(monthIdx + 1).padStart(2, "0");
    const from = `${year}-${month}-01`;
    const to = `${year}-${month}-31`;
    const data = await supabase(
      `/reports?report_date=gte.${from}&report_date=lte.${to}&group_id=eq.${groupId}`
    );
    if (!data || data.length === 0) {
      return { type: "text", text: `📅 ไม่มีรายงานเดือน${monthName} ครับ` };
    }
    return buildMonthFlex(data, monthName + " " + (year + 543));
  } catch (err) {
    return { type: "text", text: "❌ ดึงข้อมูลไม่ได้: " + err.message };
  }
}

// ─── Thai Months ───────────────────────────────────────────────────────────────
const thaiMonths = ["ม.ค.","ก.พ.","มี.ค.","เม.ย.","พ.ค.","มิ.ย.","ก.ค.","ส.ค.","ก.ย.","ต.ค.","พ.ย.","ธ.ค."];

function formatThaiDate(dateStr) {
  const [y, m, d] = dateStr.split("-");
  return `${parseInt(d)} ${thaiMonths[parseInt(m)-1]} ${parseInt(y)+543}`;
}

function fmt(n) {
  return Number(n || 0).toLocaleString("th-TH", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

// ─── Flex Messages ─────────────────────────────────────────────────────────────
function buildReportFlex(title, dateStr, r) {
  return {
    type: "flex", altText: title,
    contents: {
      type: "bubble",
      header: {
        type: "box", layout: "vertical", backgroundColor: "#C0392B", paddingAll: "md",
        contents: [
          { type: "text", text: "🏪 มนชิน ซัพพลาย", color: "#FFFFFF", size: "sm", weight: "bold" },
          { type: "text", text: title, color: "#FFFFFF", size: "lg", weight: "bold" },
          { type: "text", text: dateStr, color: "#FFCCCC", size: "sm" }
        ]
      },
      body: {
        type: "box", layout: "vertical", spacing: "sm",
        contents: [
          buildRow("💵 ยอดเข้ากะ", fmt(r.cash_in) + " บาท"),
          buildRow("🛒 ยอดขาย", fmt(r.total_sales) + " บาท"),
          buildRow("📲 ยอดโอน", fmt(r.transfer) + " บาท"),
          buildRow("💰 ยอดเงินสด", fmt(r.cash_sales) + " บาท"),
          { type: "separator" },
          buildRow("🏧 เงินสดทั้งหมด", fmt(r.total_cash) + " บาท"),
          buildRow("🏦 ฝากธนาคาร", fmt(r.deposit) + " บาท"),
          buildRow("🪙 เงินคืนกะ", fmt(r.remaining) + " บาท", "#27AE60")
        ]
      },
      footer: {
        type: "box", layout: "horizontal", spacing: "sm",
        contents: [
          buildBtn("📊 ยอดวันนี้", "ยอดวันนี้"),
          buildBtn("📅 เดือนนี้", "ยอดเดือนนี้")
        ]
      }
    }
  };
}

function buildMonthFlex(rows, monthLabel) {
  const total_sales = rows.reduce((s, r) => s + Number(r.total_sales || 0), 0);
  const total_transfer = rows.reduce((s, r) => s + Number(r.transfer || 0), 0);
  const total_deposit = rows.reduce((s, r) => s + Number(r.deposit || 0), 0);
  const total_cash = rows.reduce((s, r) => s + Number(r.cash_sales || 0), 0);
  return {
    type: "flex", altText: "สรุปยอดเดือน " + monthLabel,
    contents: {
      type: "bubble",
      header: {
        type: "box", layout: "vertical", backgroundColor: "#C0392B", paddingAll: "md",
        contents: [
          { type: "text", text: "🏪 มนชิน ซัพพลาย", color: "#FFFFFF", size: "sm", weight: "bold" },
          { type: "text", text: "📅 สรุปยอดประจำเดือน", color: "#FFFFFF", size: "lg", weight: "bold" },
          { type: "text", text: monthLabel + " (" + rows.length + " วัน)", color: "#FFCCCC", size: "sm" }
        ]
      },
      body: {
        type: "box", layout: "vertical", spacing: "sm",
        contents: [
          buildRow("🛒 ยอดขายรวม", fmt(total_sales) + " บาท"),
          buildRow("📲 ยอดโอนรวม", fmt(total_transfer) + " บาท"),
          buildRow("💰 ยอดเงินสดรวม", fmt(total_cash) + " บาท"),
          { type: "separator" },
          buildRow("🏦 ฝากธนาคารรวม", fmt(total_deposit) + " บาท", "#27AE60"),
          buildRow("📋 รายงานทั้งหมด", rows.length + " ครั้ง")
        ]
      },
      footer: {
        type: "box", layout: "horizontal", spacing: "sm",
        contents: [buildBtn("🗓️ เลือกเดือน", "สรุปยอด")]
      }
    }
  };
}

function buildRow(label, value, color) {
  return {
    type: "box", layout: "horizontal",
    contents: [
      { type: "text", text: label, size: "sm", color: "#555555", flex: 3 },
      { type: "text", text: value, size: "sm", weight: "bold", color: color || "#1A1A1A", flex: 2, align: "end" }
    ]
  };
}

function buildBtn(label, text) {
  return {
    type: "button", style: "secondary", height: "sm",
    action: { type: "message", label, text }
  };
}

function buildLiffMessage() {
  return {
    type: "template", altText: "กดเพื่อเปิดฟอร์มฝากเงิน",
    template: {
      type: "buttons",
      title: "รายงานฝากเงินประจำวัน",
      text: "กดปุ่มด้านล่างเพื่อกรอกรายละเอียดและแนบสลิป",
      actions: [{ type: "uri", label: "เปิดฟอร์มฝากเงิน", uri: "https://liff.line.me/" + process.env.LIFF_ID }]
    }
  };
}

function buildMenuMessage() {
  return {
    type: "flex", altText: "เมนูคำสั่ง",
    contents: {
      type: "bubble",
      header: {
        type: "box", layout: "vertical", backgroundColor: "#C0392B", paddingAll: "md",
        contents: [
          { type: "text", text: "🏪 มนชิน ซัพพลาย", color: "#FFFFFF", size: "md", weight: "bold" },
          { type: "text", text: "เลือกคำสั่งที่ต้องการ", color: "#FFCCCC", size: "sm" }
        ]
      },
      body: {
        type: "box", layout: "vertical", spacing: "sm",
        contents: [
          {
            type: "box", layout: "horizontal", spacing: "sm",
            contents: [
              { type: "button", style: "primary", color: "#C0392B", action: { type: "message", label: "📋 ฝากเงิน", text: "ฝากเงิน" } },
              { type: "button", style: "primary", color: "#2980B9", action: { type: "message", label: "📊 ยอดวันนี้", text: "ยอดวันนี้" } }
            ]
          },
          {
            type: "box", layout: "horizontal", spacing: "sm",
            contents: [
              { type: "button", style: "primary", color: "#27AE60", action: { type: "message", label: "📅 ยอดเดือนนี้", text: "ยอดเดือนนี้" } },
              { type: "button", style: "primary", color: "#E67E22", action: { type: "message", label: "🗓️ สรุปยอด", text: "สรุปยอด" } }
            ]
          }
        ]
      }
    }
  };
}

function buildSummaryMenu() {
  const now = new Date();
  const year = now.getFullYear();
  const curMonth = now.getMonth();
  const months = [];
  for (let i = 5; i >= 0; i--) {
    const idx = (curMonth - i + 12) % 12;
    months.push({ label: thaiMonths[idx], text: "เดือน:" + thaiMonths[idx] });
  }
  return {
    type: "flex", altText: "เลือกเดือน",
    contents: {
      type: "bubble",
      header: {
        type: "box", layout: "vertical", backgroundColor: "#C0392B", paddingAll: "md",
        contents: [{ type: "text", text: "🗓️ เลือกเดือนที่ต้องการ", color: "#FFFFFF", size: "md", weight: "bold" }]
      },
      body: {
        type: "box", layout: "vertical", spacing: "sm",
        contents: [
          {
            type: "box", layout: "horizontal", spacing: "sm",
            contents: months.slice(0, 3).map(m => ({
              type: "button", style: "secondary", height: "sm",
              action: { type: "message", label: m.label, text: m.text }
            }))
          },
          {
            type: "box", layout: "horizontal", spacing: "sm",
            contents: months.slice(3, 6).map(m => ({
              type: "button",
              style: m.label === thaiMonths[curMonth] ? "primary" : "secondary",
              color: m.label === thaiMonths[curMonth] ? "#C0392B" : undefined,
              height: "sm",
              action: { type: "message", label: m.label + (m.label === thaiMonths[curMonth] ? " ●" : ""), text: m.text }
            }))
          }
        ]
      }
    }
  };
}

app.get("/", (req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port " + PORT));
