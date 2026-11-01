import type { FirewallConfig } from "./config";

export type BlockReason =
  | "empty_key"
  | "path_too_long"
  | "control_char"
  | "backslash"
  | "encoded_separator"
  | "bad_encoding"
  | "double_encoded"
  | "traversal"
  | "dotfile"
  | "segment_too_long"
  | "key_too_long"
  | "extension_required"
  | "extension_not_allowed"
  | "bad_referer"
  | "hotlink"
  | "bad_signature"
  | "rate_limited"
  | "method_not_allowed"
  | "range_invalid"
  | "upstream_error";

export interface Block {
  reason: BlockReason;
  status: 400 | 403 | 404 | 405 | 416 | 429 | 502;
}

export type KeyResult = { ok: true; key: string } | { ok: false; block: Block };

/** 不可见/双向控制字符，可被用来做视觉欺骗与缓存投毒 */
const FORBIDDEN_UNICODE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

/**
 * 把请求路径归一化为 R2 对象键。任何无法被明确、无歧义地映射的情况一律拒绝，
 * 不做"尽力猜测"——猜测出来的键正是绕过与越权的入口。
 */
export const resolveObjectKey = (pathname: string, cfg: FirewallConfig): KeyResult => {
  // 0. 长度前置检查，避免对超长输入做后续处理
  if (pathname.length > cfg.keyMaxLength * 4 + 64) {
    return { ok: false, block: { reason: "path_too_long", status: 400 } };
  }

  // 1. 编码的分隔符：%2f / %5c 解出来会凭空多出目录层级，语义与原始键不一致，直接拒
  if (/%2f|%5c|%2F|%5C/.test(pathname)) {
    return { ok: false, block: { reason: "encoded_separator", status: 400 } };
  }

  // 2. 反斜杠：Windows 风格分隔符容易被不同层理解成不同路径
  if (pathname.includes("\\")) {
    return { ok: false, block: { reason: "backslash", status: 400 } };
  }

  // 3. 解码一次；失败说明有裸 % 或残缺百分号转义
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return { ok: false, block: { reason: "bad_encoding", status: 400 } };
  }

  // 4. 二次编码探测：%252e%252e 这类要先解码两遍才现形，反过来就是典型的穿越绕过。
  //    单层编码里合法的字面 % （如 /100%25DSC.jpg）二次解码会抛错，属于允许情况。
  try {
    const twice = decodeURIComponent(decoded);
    if (twice !== decoded) {
      return { ok: false, block: { reason: "double_encoded", status: 400 } };
    }
  } catch {
    /* 单层编码的正常形态，放行 */
  }

  if (CONTROL_CHARS.test(decoded)) {
    return { ok: false, block: { reason: "control_char", status: 400 } };
  }
  if (decoded.includes("\\")) {
    return { ok: false, block: { reason: "backslash", status: 400 } };
  }
  if (FORBIDDEN_UNICODE.test(decoded)) {
    return { ok: false, block: { reason: "control_char", status: 400 } };
  }

  // 5. 逐段归一化：丢掉空段与 "."，遇 ".." 直接拒（不做"回退一层"的解释）
  const segments: string[] = [];
  for (const raw of decoded.split("/")) {
    if (raw === "" || raw === ".") continue;
    if (raw === "..") {
      return { ok: false, block: { reason: "traversal", status: 400 } };
    }
    if (raw.length > cfg.segmentMaxLength) {
      return { ok: false, block: { reason: "segment_too_long", status: 400 } };
    }
    if (raw.startsWith(".") && !cfg.allowDotfiles) {
      return { ok: false, block: { reason: "dotfile", status: 403 } };
    }
    segments.push(raw);
  }

  if (segments.length === 0) {
    return { ok: false, block: { reason: "empty_key", status: 404 } };
  }

  const key = segments.join("/");
  if (key.length > cfg.keyMaxLength) {
    return { ok: false, block: { reason: "key_too_long", status: 400 } };
  }

  // 6. 扩展名策略
  const last = segments[segments.length - 1] as string;
  const dot = last.lastIndexOf(".");
  const ext = dot > 0 ? last.slice(dot + 1).toLowerCase() : "";

  if (ext === "") {
    if (cfg.enforceExtension) {
      return { ok: false, block: { reason: "extension_required", status: 403 } };
    }
  } else if (cfg.allowedExtensions.size > 0 && !cfg.allowedExtensions.has(ext)) {
    return { ok: false, block: { reason: "extension_not_allowed", status: 403 } };
  }

  return { ok: true, key };
};

const hostMatches = (host: string, allowed: readonly string[]): boolean => {
  for (const entry of allowed) {
    if (host === entry) return true;
    if (host.endsWith(`.${entry}`)) return true;
  }
  return false;
};

/** 热链检查：无 Referer 视为直连放行（bookmark / curl / referrerPolicy=no-referrer） */
export const checkReferer = (
  referer: string | null,
  requestHost: string,
  cfg: FirewallConfig,
): Block | null => {
  if (cfg.hotlinkMode === "off") return null;
  if (!referer) return null;

  let host: string;
  try {
    host = new URL(referer).hostname.toLowerCase();
  } catch {
    return { reason: "bad_referer", status: 403 };
  }

  if (host === requestHost.toLowerCase()) return null;
  if (hostMatches(host, cfg.allowedRefererHosts)) return null;
  return { reason: "hotlink", status: 403 };
};

/** CORS 反射判断：只对白名单 origin 回显 ACAO，避免公开可读放大盗链 */
export const originAllowed = (origin: string | null, cfg: FirewallConfig): boolean => {
  if (!origin) return false;
  let host: string;
  try {
    host = new URL(origin).hostname.toLowerCase();
  } catch {
    return false;
  }
  return hostMatches(host, cfg.allowedOriginHosts);
};
