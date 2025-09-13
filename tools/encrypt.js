// tools/encrypt.js
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.join(__dirname, "..");
const contentPath = path.join(repoRoot, "content.json");
const outPath = path.join(repoRoot, "ciphers.js");

if (!fs.existsSync(contentPath)) {
  console.error("❌ content.json tidak ditemukan");
  process.exit(1);
}

// Ambil password 3 digit dari env atau argumen --pw=123
const arg = process.argv.find(a => a.startsWith("--pw="));
const PW = (process.env.PW || (arg ? arg.split("=")[1] : "")).trim();

if (!/^\d{3}$/.test(PW)) {
  console.error("❌ Password wajib 3 digit, contoh: --pw=123 atau set env PW=123");
  process.exit(1);
}

const iters = 100000;
const salt = crypto.randomBytes(16);
const iv   = crypto.randomBytes(12);

const content = JSON.stringify(JSON.parse(fs.readFileSync(contentPath, "utf8")));
const key  = crypto.pbkdf2Sync(PW, salt, iters, 32, "sha256");

const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const enc = Buffer.concat([cipher.update(Buffer.from(content, "utf8")), cipher.final()]);
const tag = cipher.getAuthTag();
const ctAndTag = Buffer.concat([enc, tag]);

const item = {
  salt_b64: salt.toString("base64"),
  iv_b64: iv.toString("base64"),
  iters,
  data_b64: ctAndTag.toString("base64"),
  note: `manual: pw=${PW}, UTC=${new Date().toISOString().slice(0,10)}`
};

const js = `// Generated ${new Date().toISOString()}
window.CIPHERS = [ ${JSON.stringify(item, null, 2)} ];
`;

fs.writeFileSync(outPath, js);
console.log("✅ ciphers.js dibuat. Password aktif:", PW);
