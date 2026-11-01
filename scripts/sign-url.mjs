#!/usr/bin/env node
/**
 * 生成带签名的访问链接（对应 worker 内 src/firewall/signature.ts）。
 *
 *   URL_SIGNING_SECRET=xxx node scripts/sign-url.mjs /2026/photo.jpg --ttl 3600
 *   node scripts/sign-url.mjs /2026/photo.jpg --ttl 86400 --secret xxx --base https://postpic.iicemeta.com
 *
 * 签名串：BASE64URL(HMAC-SHA256(secret, `${key}\n${exp}`))
 * key 用的是清洗后的对象键（无前导斜杠），不是原始 URL path。
 */
import { createHmac } from "node:crypto";

const argv = process.argv.slice(2);
const flags = new Map();
const positional = [];

for (let i = 0; i < argv.length; i += 1) {
  const arg = argv[i];
  if (arg.startsWith("--")) {
    const [name, inline] = arg.slice(2).split("=");
    if (inline !== undefined) flags.set(name, inline);
    else if (argv[i + 1] && !argv[i + 1].startsWith("--")) {
      flags.set(name, argv[i + 1]);
      i += 1;
    } else flags.set(name, "true");
  } else positional.push(arg);
}

const secret = flags.get("secret") ?? process.env.URL_SIGNING_SECRET ?? "";
const rawKey = positional[0];
const ttl = Number(flags.get("ttl") ?? 3600);
const base = (flags.get("base") ?? "").replace(/\/+$/, "");

if (!secret) {
  console.error("缺少密钥：设置 URL_SIGNING_SECRET 环境变量或传 --secret");
  process.exit(1);
}
if (!rawKey) {
  console.error("缺少对象键：node scripts/sign-url.mjs /path/to/object.jpg");
  process.exit(1);
}
// Git Bash / MSYS 会把 /foo/bar 这类参数改写成 C:/... 的 Windows 路径，
// 一旦发生，签出来的键和真实对象键必然对不上，这里直接拦掉而不是生成一个坏链接。
if (/^[A-Za-z]:[\\/]/.test(rawKey) || rawKey.includes("\\")) {
  console.error(
    `对象键被 shell 改写成 Windows 路径：${rawKey}\n` +
      "请用 MSYS_NO_PATHCONV=1 前缀重跑，或改用不以斜杠开头的相对键。",
  );
  process.exit(1);
}
if (!Number.isFinite(ttl) || ttl <= 0) {
  console.error("--ttl 必须是正数秒");
  process.exit(1);
}

const key = rawKey.replace(/^\/+/, "");
const exp = String(Math.floor(Date.now() / 1000) + Math.floor(ttl));
const sig = createHmac("sha256", secret)
  .update(`${key}\n${exp}`)
  .digest("base64")
  .replace(/\+/g, "-")
  .replace(/\//g, "_")
  .replace(/=+$/, "");

const query = `exp=${exp}&sig=${sig}`;
const url = base ? `${base}/${key}?${query}` : `/${key}?${query}`;

if (flags.get("json")) {
  console.log(JSON.stringify({ key, exp: Number(exp), sig, url }, null, 2));
} else {
  console.log(url);
}
