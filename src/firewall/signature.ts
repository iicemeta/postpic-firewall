/**
 * 可选：URL 签名。
 *
 * 设了 URL_SIGNING_SECRET 后，只有带 `exp`（Unix 秒）和 `sig` 的链接才能取到对象：
 *
 *   sig = BASE64URL(HMAC-SHA256(secret, `${key}\n${exp}`))
 *
 * 这是对"盗刷"最硬的防线——被抄走的链接会在 exp 之后自动失效，
 * 不必依赖 Referer（可被伪造）或 UA（可被伪造）。
 */

let keyCache: { secret: string; key: Promise<CryptoKey> } | null = null;

const getKey = (secret: string): Promise<CryptoKey> => {
  if (keyCache && keyCache.secret === secret) return keyCache.key;
  const key = crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  keyCache = { secret, key };
  return key;
};

const base64url = (buf: ArrayBuffer): string => {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const sign = async (key: string, exp: string, secret: string): Promise<string> => {
  const cryptoKey = await getKey(secret);
  const mac = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(`${key}\n${exp}`));
  return base64url(mac);
};

/** 常量时间比较，避免按字节提前返回泄漏信息 */
const timingSafeEqual = (a: string, b: string): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

export const verifySignature = async (
  objectKey: string,
  exp: string | null,
  sig: string | null,
  secret: string,
): Promise<boolean> => {
  if (!exp || !sig) return false;

  const expNum = Number(exp);
  if (!Number.isFinite(expNum)) return false;
  const now = Math.floor(Date.now() / 1000);
  if (expNum <= now) return false;
  // 超长有效期等于没签名，限制在 30 天内
  if (expNum - now > 30 * 24 * 3600) return false;

  const expected = await sign(objectKey, exp, secret);
  return timingSafeEqual(expected, sig);
};
