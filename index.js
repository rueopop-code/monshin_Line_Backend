require("dotenv").config();
const express = require("express");
const line = require("@line/bot-sdk");
const path = require("path");

const app = express();

// ─── Serve static files จาก public/ ──────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

const lineConfig = {
  channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
  channelSecret: process.env.LINE_CHANNEL_SECRET,
};
const client = new line.messagingApi.MessagingApiClient(lineConfig);

const SUPABASE_URL = process.env.SUPABASE_URL || "https://mnilcsbyhtmauvuadrjs.supabase.co";
const SUPABASE_KEY = process.env.SUPABASE_KEY;

// ─── Supabase Helper ───────────────────────────────────────────────────────────
async function supabase(path, method = "GET", body = null) {
  const axios = require("axios");
  const headers = {
    "Content-Type": "application/json",
    "apikey": SUPABASE_KEY,
    "Authorization": "Bearer " + SUPABASE_KEY,
    "Prefer": method === "POST" ? "return=minimal" : ""
  };
  const url = SUPABASE_URL + "/rest/v1" + path;
  console.log("[supabase]", method, url);
  try {
    const res = await axios({ method, url, headers, data: body || undefined });
    if (res.status === 204 || res.status === 201) return null;
    return res.data;
  } catch(err) {
    if (err.response && (err.response.status === 204 || err.response.status === 201)) return null;
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error("[supabase error]", method, url, "→", detail);
    throw new Error(detail);
  }
}

// ─── บันทึกรายงานลง Supabase ──────────────────────────────────────────────────
app.post("/save-report", express.json({ limit: "1mb" }), async (req, res) => {
  try {
    const raw = req.body;

    // ป้องกัน field ที่ไม่ตรง — map เฉพาะ column ที่มีใน table
    const data = {
      report_date:    raw.report_date    || new Date().toISOString().split("T")[0],
      cash_in:        Number(raw.cash_in        || 0),
      total_sales:    Number(raw.total_sales    || 0),
      transfer:       Number(raw.transfer       || 0),
      cash_sales:     Number(raw.cash_sales     || 0),
      total_cash:     Number(raw.total_cash     || 0),
      deposit:        Number(raw.deposit        || 0),
      remaining:      Number(raw.remaining      || 0),
      depositor_name: raw.depositor_name || "",
      diff_amount:    Number(raw.diff_amount    || 0),
      diff_type:      raw.diff_type      || "plus",
      note:           raw.note           || "",
      slip_url:       raw.slip_url       || "",
      group_id:       raw.group_id       || "",
    };

    console.log("save-report payload:", JSON.stringify(data));
    await supabase("/reports", "POST", data);
    console.log("save-report: success");
    res.json({ success: true });
  } catch (err) {
    // พิมพ์ทั้ง response body จาก Supabase เพื่อ debug
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error("save-report error:", detail);
    res.status(500).json({ success: false, error: detail });
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
app.post("/webhook", express.json(), async (req, res) => {
  // ตรวจ signature เอง — ถ้าไม่ผ่านให้ข้ามแทนที่จะ error 400
  try {
    const signature = req.headers["x-line-signature"];
    if (signature) {
      const crypto = require("crypto");
      const body = JSON.stringify(req.body);
      const hash = crypto.createHmac("sha256", lineConfig.channelSecret)
        .update(body).digest("base64");
      if (hash !== signature) {
        console.warn("Invalid signature — skipping");
        return res.sendStatus(200);
      }
    }
  } catch(e) {
    console.warn("Signature check error:", e.message);
  }

  res.sendStatus(200);
  const events = req.body.events || [];
  for (const event of events) {
    await handleEvent(event);
  }
});

async function handleEvent(event) {
  if (!["message", "postback"].includes(event.type)) return;
  // รับทั้ง group, room, และ user (1:1 กับ OA)
  if (!["group", "room", "user"].includes(event.source.type)) return;

  const replyToken = event.replyToken;
  const groupId = event.source.groupId || event.source.roomId || "";
  const userId = event.source.userId || "";
  const isUser = event.source.type === "user"; // 1:1 กับ OA

  // helper: ส่งข้อความกลับด้วย replyToken เสมอ พร้อม error handling
  const reply = async (messages) => {
    try {
      await client.replyMessage({ replyToken, messages });
    } catch(e) {
      console.error("reply error:", e.message);
    }
  };

  // ถ้าเป็น 1:1 และไม่มี groupId ให้ดึง groupId ล่าสุดจาก Supabase
  let resolvedGroupId = groupId;
  if (!groupId && isUser) {
    try {
      const latest = await supabase("/reports?order=created_at.desc&limit=1");
      if (latest && latest.length > 0 && latest[0].group_id) {
        resolvedGroupId = latest[0].group_id;
      }
    } catch(e) {
      console.warn("ดึง group_id ล่าสุดไม่ได้:", e.message);
    }
  }

  // ─── Postback handler ───────────────────────────────────────────────────────
  if (event.type === "postback") {
    const data = event.postback.data;
    if (data === "ยอดวันนี้") {
      const msg = await getTodayReport(resolvedGroupId);
      await reply([msg]);
    } else if (data === "ยอดเดือนนี้") {
      const msg = await getMonthReport(resolvedGroupId);
      await reply([msg]);
    } else if (data === "สรุปยอด") {
      await reply([buildSummaryMenu()]);
    } else if (data.startsWith("เดือน:")) {
      const monthStr = data.replace("เดือน:", "").trim();
      const msg = await getMonthReportByName(resolvedGroupId, monthStr);
      await reply([msg]);
    } else if (data === "ประวัติ") {
      await reply([buildHistoryMonthMenu()]);
    } else if (data.startsWith("ประวัติเดือน:")) {
      const monthStr = data.replace("ประวัติเดือน:", "").trim();
      const msg = await buildHistoryDateMenu(resolvedGroupId, monthStr);
      await reply([msg]);
    } else if (data.startsWith("ประวัติวันที่:")) {
      const dateStr = data.replace("ประวัติวันที่:", "").trim();
      const msgs = await getHistoryByDate(resolvedGroupId, dateStr);
      await reply(msgs.slice(0, 5));
    }
    return;
  }

  if (event.message.type === "text") {
    const text = event.message.text.trim();

    if (["ฝากเงิน", "รายงาน", "เปิดฟอร์ม"].includes(text)) {
      await reply([buildLiffMessage(resolvedGroupId)]);

    } else if (text === "เมนู" || text === "menu") {
      await reply([buildMenuMessage()]);

    } else if (text === "ยอดวันนี้") {
      const msg = await getTodayReport(resolvedGroupId);
      await reply([msg]);

    } else if (text === "ยอดเดือนนี้") {
      const msg = await getMonthReport(resolvedGroupId);
      await reply([msg]);

    } else if (text === "สรุปยอด") {
      await reply([buildSummaryMenu()]);

    } else if (text.startsWith("เดือน:")) {
      const monthStr = text.replace("เดือน:", "").trim();
      const msg = await getMonthReportByName(resolvedGroupId, monthStr);
      await reply([msg]);

    } else if (text === "ประวัติ") {
      await reply([buildHistoryMonthMenu()]);

    } else if (text.startsWith("ประวัติเดือน:")) {
      const monthStr = text.replace("ประวัติเดือน:", "").trim();
      const msg = await buildHistoryDateMenu(resolvedGroupId, monthStr);
      await reply([msg]);

    } else if (text.startsWith("ประวัติวันที่:")) {
      const dateStr = text.replace("ประวัติวันที่:", "").trim();
      const msgs = await getHistoryByDate(resolvedGroupId, dateStr);
      await reply(msgs.slice(0, 5));
    }
  }
}

// ─── helper: วันที่ปัจจุบันเวลาไทย UTC+7 ──────────────────────────────────────
function getTodayTH() {
  const now = new Date();
  const th = new Date(now.getTime() + 7 * 60 * 60 * 1000);
  return th.toISOString().split("T")[0];
}

// ─── ดึงยอดวันนี้ (แสดงทุกกะ แยกตามชื่อผู้ฝาก) ────────────────────────────────
async function getTodayReport(groupId) {
  try {
    const today = getTodayTH();
    const data = await supabase(
      `/reports?report_date=eq.${today}&group_id=eq.${encodeURIComponent(groupId)}&order=created_at.asc`
    );
    if (!data || data.length === 0) {
      return { type: "text", text: "📊 ยังไม่มีรายงานวันนี้ครับ\nพิมพ์ \"ฝากเงิน\" เพื่อเปิดฟอร์ม" };
    }
    if (data.length === 1) {
      return buildReportFlex("📊 ยอดวันนี้", formatThaiDate(data[0].report_date), data[0]);
    }
    // หลายกะ — แสดงสรุปรวม + แต่ละกะ
    return buildTodayMultiFlex(data, formatThaiDate(today));
  } catch (err) {
    return { type: "text", text: "❌ ดึงข้อมูลไม่ได้ครับ: " + err.message };
  }
}

function buildTodayMultiFlex(rows, dateStr) {
  const totalSales = rows.reduce((s, r) => s + Number(r.total_sales || 0), 0);
  const totalDeposit = rows.reduce((s, r) => s + Number(r.deposit || 0), 0);
  const totalRemaining = rows.reduce((s, r) => s + Number(r.remaining || 0), 0);

  const shiftRows = rows.map((r, i) => ({
    type: "box", layout: "vertical", margin: "md",
    borderWidth: "1px", borderColor: "#DDDDDD", cornerRadius: "md",
    paddingAll: "sm",
    contents: [
      {
        type: "box", layout: "horizontal",
        contents: [
          { type: "text", text: "กะที่ " + (i+1) + " — " + (r.depositor_name || "ไม่ระบุ"), size: "sm", weight: "bold", color: "#C0392B", flex: 1 },
          { type: "text", text: "฿" + fmt(r.total_sales), size: "sm", color: "#555555", align: "end" }
        ]
      },
      buildRow("💵 เข้ากะ", fmt(r.cash_in) + " บาท"),
      buildRow("🏦 ฝาก", fmt(r.deposit) + " บาท"),
      buildRow("🪙 คืนกะ", fmt(r.remaining) + " บาท", Number(r.remaining) >= 0 ? "#27AE60" : "#E74C3C")
    ]
  }));

  return {
    type: "flex", altText: "ยอดวันนี้ " + dateStr + " (" + rows.length + " กะ)",
    contents: {
      type: "bubble",
      header: {
        type: "box", layout: "vertical", backgroundColor: "#C0392B", paddingAll: "md",
        contents: [
          { type: "text", text: "🏪 มนชิน ซัพพลาย", color: "#FFFFFF", size: "sm", weight: "bold" },
          { type: "text", text: "📊 ยอดวันนี้ (" + rows.length + " กะ)", color: "#FFFFFF", size: "lg", weight: "bold" },
          { type: "text", text: dateStr, color: "#FFCCCC", size: "sm" }
        ]
      },
      body: {
        type: "box", layout: "vertical", spacing: "sm",
        contents: [
          buildRow("🛒 ยอดขายรวม", fmt(totalSales) + " บาท"),
          buildRow("🏦 ฝากรวม", fmt(totalDeposit) + " บาท"),
          buildRow("🪙 คืนกะรวม", fmt(totalRemaining) + " บาท", "#27AE60"),
          { type: "separator", margin: "md" },
          { type: "text", text: "รายละเอียดแต่ละกะ", size: "sm", weight: "bold", color: "#555555", margin: "md" },
          ...shiftRows
        ]
      },
      footer: {
        type: "box", layout: "horizontal", spacing: "sm",
        contents: [buildBtn("📅 เดือนนี้", "ยอดเดือนนี้"), buildBtn("🗓️ เลือกเดือน", "สรุปยอด")]
      }
    }
  };
}

// ─── ดึงยอดเดือนนี้ ────────────────────────────────────────────────────────────
async function getMonthReport(groupId) {
  try {
    if (!groupId) return { type: "text", text: "❌ ไม่พบ group_id กรุณาใช้ในกลุ่ม LINE ครับ" };
    const now = new Date(new Date().getTime() + 7 * 60 * 60 * 1000); // UTC+7
    const year = now.getUTCFullYear();
    const monthNum = now.getUTCMonth() + 1;
    const month = String(monthNum).padStart(2, "0");
    const lastDay = new Date(year, monthNum, 0).getDate();
    const from = `${year}-${month}-01`;
    const to = `${year}-${month}-${String(lastDay).padStart(2, "0")}`;
    const data = await supabase(
      `/reports?report_date=gte.${from}&report_date=lte.${to}&group_id=eq.${encodeURIComponent(groupId)}&order=report_date.asc`
    );
    if (!data || data.length === 0) {
      return { type: "text", text: "📅 ยังไม่มีรายงานเดือนนี้ครับ" };
    }
    return buildMonthFlex(data, thaiMonths[now.getUTCMonth()] + " " + (year + 543));
  } catch (err) {
    return { type: "text", text: "❌ ดึงข้อมูลไม่ได้ครับ: " + err.message };
  }
}

// ─── ดึงยอดตามเดือนที่เลือก ────────────────────────────────────────────────────
async function getMonthReportByName(groupId, monthName) {
  try {
    if (!groupId) return { type: "text", text: "❌ ไม่พบ group_id กรุณาใช้ในกลุ่ม LINE ครับ" };
    const now = new Date(new Date().getTime() + 7 * 60 * 60 * 1000); // UTC+7
    const year = now.getUTCFullYear();
    const monthIdx = thaiMonths.indexOf(monthName);
    if (monthIdx === -1) return { type: "text", text: "❌ ไม่พบเดือน: " + monthName };
    const monthNum = monthIdx + 1;
    const month = String(monthNum).padStart(2, "0");
    const lastDay = new Date(year, monthNum, 0).getDate();
    const from = `${year}-${month}-01`;
    const to = `${year}-${month}-${String(lastDay).padStart(2, "0")}`;
    const data = await supabase(
      `/reports?report_date=gte.${from}&report_date=lte.${to}&group_id=eq.${encodeURIComponent(groupId)}&order=report_date.asc`
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
    action: { type: "postback", label, data: text, displayText: label }
  };
}

// ─── ประวัติ: เลือกเดือน ──────────────────────────────────────────────────────
function buildHistoryMonthMenu() {
  const now = new Date(new Date().getTime() + 7 * 60 * 60 * 1000);
  const curMonth = now.getUTCMonth();
  const lines = [];
  for (let i = 5; i >= 0; i--) {
    const idx2 = (curMonth - i + 12) % 12;
    const mark = idx2 === curMonth ? " ●" : "";
    lines.push("• " + thaiMonths[idx2] + mark + "  →  พิมพ์: ประวัติเดือน:" + thaiMonths[idx2]);
  }
  return {
    type: "text",
    text: "📂 ดูประวัติรายงาน\nพิมพ์ชื่อเดือนที่ต้องการ:\n\n" + lines.join("\n") + "\n\nตัวอย่าง: ประวัติเดือน:มิ.ย."
  };
}

// ─── ประวัติ: เลือกวันที่ ──────────────────────────────────────────────────────
async function buildHistoryDateMenu(groupId, monthName) {
  try {
    const now = new Date();
    const year = now.getFullYear();
    const monthIdx = thaiMonths.indexOf(monthName);
    if (monthIdx === -1) return { type: "text", text: "❌ ไม่พบเดือน: " + monthName };
    const month = String(monthIdx + 1).padStart(2, "0");
    const lastDay = new Date(year, monthIdx + 1, 0).getDate();
    const from = year + "-" + month + "-01";
    const to = year + "-" + month + "-" + String(lastDay).padStart(2, "0");
    if (!groupId) return { type: "text", text: "❌ ไม่พบ group_id กรุณาใช้ในกลุ่ม LINE ครับ" };
    const data = await supabase(
      "/reports?report_date=gte." + from + "&report_date=lte." + to + "&group_id=eq." + encodeURIComponent(groupId) + "&order=report_date.asc"
    );
    if (!data || data.length === 0) {
      return { type: "text", text: "📂 ไม่มีรายงานเดือน" + monthName + " ครับ" };
    }
    // หาวันที่ที่มีข้อมูล (unique)
    const uniqueDates = [...new Set(data.map(r => r.report_date))];
    const dateButtons = uniqueDates.map(d => {
      const [y, m, day] = d.split("-");
      const label = parseInt(day) + " " + thaiMonths[parseInt(m)-1];
      const count = data.filter(r => r.report_date === d).length;
      return {
        type: "button", style: "secondary", height: "sm",
        action: { type: "message", label: label + " (" + count + ")", text: "ประวัติวันที่:" + d }
      };
    });

    // แบ่งเป็นแถวละ 3 ปุ่ม
    const rows = [];
    for (let i = 0; i < dateButtons.length; i += 3) {
      rows.push({ type: "box", layout: "horizontal", spacing: "sm", contents: dateButtons.slice(i, i+3) });
    }

    // ถ้าไม่มีวันที่เลย
    if (rows.length === 0) {
      return { type: "text", text: "📂 ไม่มีรายงานเดือน" + monthName + " ครับ" };
    }

    return {
      type: "flex", altText: "เลือกวันที่ — " + monthName,
      contents: {
        type: "bubble",
        header: {
          type: "box", layout: "vertical", backgroundColor: "#2C3E50", paddingAll: "md",
          contents: [
            { type: "text", text: "📂 ประวัติเดือน" + monthName, color: "#FFFFFF", size: "md", weight: "bold" },
            { type: "text", text: "กดวันที่ต้องการดู (" + data.length + " รายการ)", color: "#BDC3C7", size: "sm" }
          ]
        },
        body: { type: "box", layout: "vertical", spacing: "sm", contents: rows }
      }
    };
  } catch(err) {
    return { type: "text", text: "❌ เกิดข้อผิดพลาด: " + err.message };
  }
}

// ─── ประวัติ: ดูรายงาน + สลิปของวันนั้น ────────────────────────────────────────
async function getHistoryByDate(groupId, dateStr) {
  try {
    const data = await supabase(
      "/reports?report_date=eq." + dateStr + "&group_id=eq." + encodeURIComponent(groupId) + "&order=created_at.asc"
    );
    if (!data || data.length === 0) {
      return [{ type: "text", text: "📂 ไม่มีรายงานวันที่ " + formatThaiDate(dateStr) + " ครับ" }];
    }

    const msgs = [];

    // Header text
    msgs.push({
      type: "text",
      text: "📂 ประวัติวันที่ " + formatThaiDate(dateStr) + "\nมีทั้งหมด " + data.length + " รายการ"
    });

    // แต่ละรายการ
    for (let i = 0; i < data.length && i < 4; i++) {
      const r = data[i];
      const depositor = r.depositor_name || "ไม่ระบุ";
      msgs.push({
        type: "flex", altText: "รายการที่ " + (i+1) + " — " + depositor,
        contents: {
          type: "bubble",
          header: {
            type: "box", layout: "vertical", backgroundColor: "#2C3E50", paddingAll: "md",
            contents: [
              { type: "text", text: "📋 รายการที่ " + (i+1) + " — " + depositor, color: "#FFFFFF", size: "sm", weight: "bold" },
              { type: "text", text: formatThaiDate(r.report_date), color: "#BDC3C7", size: "xs" }
            ]
          },
          body: {
            type: "box", layout: "vertical", spacing: "sm",
            contents: [
              buildRow("💵 ยอดเข้ากะ", fmt(r.cash_in) + " บาท"),
              buildRow("🛒 ยอดขาย", fmt(r.total_sales) + " บาท"),
              buildRow("📲 ยอดโอน", fmt(r.transfer) + " บาท"),
              buildRow("🏦 ฝากธนาคาร", fmt(r.deposit) + " บาท"),
              buildRow("🪙 เงินคืนกะ", fmt(r.remaining) + " บาท", Number(r.remaining) >= 0 ? "#27AE60" : "#E74C3C"),
              ...(r.note ? [buildRow("📝 หมายเหตุ", r.note)] : []),
              ...(r.diff_amount > 0 ? [buildRow(r.diff_type === "plus" ? "✅ ผลบวก" : "❌ ผลลบ", fmt(r.diff_amount) + " บาท")] : []),
              ...(r.slip_url ? [{
                type: "button", style: "primary", color: "#27AE60",
                action: { type: "uri", label: "🖼️ ดูสลิป", uri: r.slip_url }
              }] : [{ type: "text", text: "ไม่มีสลิป", size: "xs", color: "#999999" }])
            ]
          }
        }
      });
    }

    return msgs;
  } catch(err) {
    return [{ type: "text", text: "❌ เกิดข้อผิดพลาด: " + err.message }];
  }
}

function buildLiffMessage(groupId) {
  const liffUrl = "https://liff.line.me/" + process.env.LIFF_ID + "?gid=" + encodeURIComponent(groupId || "");
  return {
    type: "template", altText: "กดเพื่อเปิดฟอร์มฝากเงิน",
    template: {
      type: "buttons",
      title: "รายงานฝากเงินประจำวัน",
      text: "กดปุ่มด้านล่างเพื่อกรอกรายละเอียดและแนบสลิป",
      actions: [{ type: "uri", label: "เปิดฟอร์มฝากเงิน", uri: liffUrl }]
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
          },
          {
            type: "box", layout: "horizontal", spacing: "sm",
            contents: [
              { type: "button", style: "primary", color: "#2C3E50", action: { type: "message", label: "📂 ประวัติ", text: "ประวัติ" } }
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
              action: { type: "postback", label: m.label, data: m.text, displayText: m.label }
            }))
          },
          {
            type: "box", layout: "horizontal", spacing: "sm",
            contents: months.slice(3, 6).map(m => ({
              type: "button",
              style: m.label === thaiMonths[curMonth] ? "primary" : "secondary",
              color: m.label === thaiMonths[curMonth] ? "#C0392B" : undefined,
              height: "sm",
              action: { type: "postback", label: m.label + (m.label === thaiMonths[curMonth] ? " ●" : ""), data: m.text, displayText: m.label }
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
