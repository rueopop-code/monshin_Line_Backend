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

async function createRichMenu() {
  console.log("1️⃣  กำลังสร้าง Rich Menu...");
  const body = {
    size: { width: 2500, height: 1686 },  // ขนาดใหม่
    selected: true,
    name: "มนชิน เมนูหลัก",
    chatBarText: "เมนูด่วน",
    areas: [
      { bounds: { x: 0,    y: 0,   width: 1250, height: 843 }, action: { type: "message", text: "ยอดวันนี้"   } },
      { bounds: { x: 1250, y: 0,   width: 1250, height: 843 }, action: { type: "message", text: "ยอดเดือนนี้" } },
      { bounds: { x: 0,    y: 843, width: 1250, height: 843 }, action: { type: "message", text: "สรุปยอด"     } },
      { bounds: { x: 1250, y: 843, width: 1250, height: 843 }, action: { type: "message", text: "ประวัติ"     } },
    ],
  };

  const res = await axios.post("https://api.line.me/v2/bot/richmenu", body, { headers });
  console.log("   ✅ Rich Menu ID:", res.data.richMenuId);
  return res.data.richMenuId;
}

async function uploadImage(richMenuId) {
  console.log("2️⃣  กำลังอัปโหลดรูป...");
  const imgPath = path.join(__dirname, "richmenu.png");
  if (!fs.existsSync(imgPath)) {
    console.error("❌ ไม่พบไฟล์ richmenu.png");
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
    { headers: { Authorization: "Bearer " + TOKEN, ...form.getHeaders() } }
  );
  console.log("   ✅ อัปโหลดรูปสำเร็จ");
}

async function setDefault(richMenuId) {
  console.log("3️⃣  กำลังตั้งเป็น Default Rich Menu...");
  await axios.post(`https://api.line.me/v2/bot/user/all/richmenu/${richMenuId}`, {}, { headers });
  console.log("   ✅ ตั้ง Default สำเร็จ");
}

async function deleteOldMenus() {
  console.log("🗑️  กำลังลบ Rich Menu เก่า...");
  try {
    const res = await axios.get("https://api.line.me/v2/bot/richmenu/list", { headers });
    const menus = res.data.richmenus || [];
    for (const m of menus) {
      await axios.delete(`https://api.line.me/v2/bot/richmenu/${m.richMenuId}`, { headers });
      console.log("   ลบ:", m.richMenuId);
    }
  } catch (e) { console.log("   (ไม่มี menu เก่า)"); }
}

async function main() {
  console.log("\n🚀 เริ่มติดตั้ง Rich Menu มนชิน ซัพพลาย\n");
  try {
    await deleteOldMenus();
    const id = await createRichMenu();
    await uploadImage(id);
    await setDefault(id);
    console.log("\n✅ ติดตั้ง Rich Menu สำเร็จแล้วครับ!");
    console.log("   เปิด LINE OA แล้วจะเห็นเมนูด้านล่างทันที\n");
  } catch (err) {
    const msg = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    console.error("\n❌ Error:", msg);
  }
}

main();
