require("dotenv").config();
const fs = require("fs");
const path = require("path");
const axios = require("axios");
const FormData = require("form-data");

const TOKEN = process.env.LINE_CHANNEL_ACCESS_TOKEN;

if (!TOKEN) {
  console.error("❌ ไม่พบ LINE_CHANNEL_ACCESS_TOKEN ใน .env");
  process.exit(1);
}

const headers = {
  Authorization: "Bearer " + TOKEN,
  "Content-Type": "application/json",
};

// ขนาด Rich Menu — ต้องตรงกับขนาดจริงของ richmenu.png เป๊ะๆ เสมอ (LINE บังคับ)
const RICHMENU_SIZE = { width: 2500, height: 843 };

// ─── 1. สร้าง Rich Menu ──────────────────────────────────────────────────────
async function createRichMenu() {
  console.log("1️⃣  กำลังสร้าง Rich Menu...");
  // แก้บั๊ก: เดิมประกาศขนาด 2500x1686 (แบบ Large, ตาราง 2x2) แต่ richmenu.png จริงมีขนาดแค่
  // 2500x843 (แบบ Compact ของ LINE) ทำให้ตอนอัปโหลดรูป (ขั้นตอนที่ 2) โดน LINE ปฏิเสธทุกครั้ง
  // เพราะขนาดรูปที่อัปโหลดต้องตรงกับ "size" ที่ประกาศไว้เป๊ะๆ เท่านั้น
  // ปรับให้ตรงกับรูปจริง: Compact size แบ่ง 4 ปุ่มเรียงแนวนอน (คอลัมน์ละ 625px)
  const body = {
    size: RICHMENU_SIZE,
    selected: true,
    name: "มนชิน เมนูหลัก",
    chatBarText: "เมนูด่วน",
    areas: [
      {
        bounds: { x: 0, y: 0, width: 625, height: 843 },
        action: { type: "message", text: "ยอดวันนี้" },
      },
      {
        bounds: { x: 625, y: 0, width: 625, height: 843 },
        action: { type: "message", text: "ยอดเดือนนี้" },
      },
      {
        bounds: { x: 1250, y: 0, width: 625, height: 843 },
        action: { type: "message", text: "สรุปยอด" },
      },
      {
        bounds: { x: 1875, y: 0, width: 625, height: 843 },
        action: { type: "message", text: "ประวัติ" },
      },
    ],
  };

  const res = await axios.post(
    "https://api.line.me/v2/bot/richmenu",
    body,
    { headers }
  );
  console.log("   ✅ Rich Menu ID:", res.data.richMenuId);
  return res.data.richMenuId;
}

// ─── 2. อัปโหลดรูป ───────────────────────────────────────────────────────────
// อ่านขนาดรูปจาก PNG header (IHDR chunk) แบบไม่ต้องพึ่ง library เพิ่ม
function readPngSize(buf) {
  if (buf.length < 24 || buf.toString("ascii", 12, 16) !== "IHDR") return null;
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

async function uploadImage(richMenuId, expectedSize) {
  console.log("2️⃣  กำลังอัปโหลดรูป...");
  const imgPath = path.join(__dirname, "richmenu.png");
  if (!fs.existsSync(imgPath)) {
    console.error("❌ ไม่พบไฟล์ richmenu.png");
    process.exit(1);
  }

  // แก้บั๊ก: เดิมไม่มีการตรวจขนาดรูปก่อนอัปโหลดเลย ถ้าขนาดไม่ตรงกับที่ประกาศไว้ตอนสร้าง Rich Menu
  // LINE จะปฏิเสธการอัปโหลดแบบไม่บอกสาเหตุชัดเจน — เช็คล่วงหน้าให้ error message เข้าใจง่ายกว่า
  const buf = fs.readFileSync(imgPath);
  const actualSize = readPngSize(buf);
  if (actualSize && (actualSize.width !== expectedSize.width || actualSize.height !== expectedSize.height)) {
    console.error(
      `❌ ขนาดรูป richmenu.png (${actualSize.width}x${actualSize.height}) ไม่ตรงกับขนาด Rich Menu ที่ประกาศไว้ ` +
      `(${expectedSize.width}x${expectedSize.height}) — แก้ไฟล์รูปหรือแก้ areas ใน createRichMenu() ให้ตรงกันก่อน`
    );
    process.exit(1);
  }

  const form = new FormData();
  form.append("image", fs.createReadStream(imgPath), {
    filename: "richmenu.png",
    contentType: "image/png",
  });

  await axios.post(
    `https://api-data.line.me/v2/bot/richmenu/${richMenuId}/content`,
    form,
    {
      headers: {
        Authorization: "Bearer " + TOKEN,
        ...form.getHeaders(),
      },
    }
  );
  console.log("   ✅ อัปโหลดรูปสำเร็จ");
}

// ─── 3. ตั้งเป็น Default Rich Menu ──────────────────────────────────────────
async function setDefault(richMenuId) {
  console.log("3️⃣  กำลังตั้งเป็น Default Rich Menu...");
  await axios.post(
    `https://api.line.me/v2/bot/user/all/richmenu/${richMenuId}`,
    {},
    { headers }
  );
  console.log("   ✅ ตั้ง Default สำเร็จ");
}

// ─── ลบ Rich Menu เก่า ───────────────────────────────────────────────────────
async function deleteOldMenus() {
  console.log("🗑️  กำลังลบ Rich Menu เก่า...");
  try {
    const res = await axios.get(
      "https://api.line.me/v2/bot/richmenu/list",
      { headers }
    );
    const menus = res.data.richmenus || [];
    for (const m of menus) {
      await axios.delete(
        `https://api.line.me/v2/bot/richmenu/${m.richMenuId}`,
        { headers }
      );
      console.log("   ลบ:", m.richMenuId);
    }
  } catch (e) {
    console.log("   (ไม่มี menu เก่า)");
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log("\n🚀 เริ่มติดตั้ง Rich Menu มนชิน ซัพพลาย\n");
  try {
    await deleteOldMenus();
    const id = await createRichMenu();
    await uploadImage(id, RICHMENU_SIZE);
    await setDefault(id);
    console.log("\n✅ ติดตั้ง Rich Menu สำเร็จแล้วครับ!");
    console.log("   เปิด LINE OA แล้วจะเห็นเมนูด้านล่างทันที\n");
  } catch (err) {
    const msg = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error("\n❌ Error:", msg);
  }
}

main();
