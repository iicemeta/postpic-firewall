import type { Env } from "../types";

export type HotlinkMode = "block" | "off";

export interface FirewallConfig {
  allowedExtensions: Set<string>;
  enforceExtension: boolean;
  allowDotfiles: boolean;
  keyMaxLength: number;
  segmentMaxLength: number;

  hotlinkMode: HotlinkMode;
  hotlinkStrict: boolean;
  allowedRefererHosts: string[];
  allowedOriginHosts: string[];
  corp: string;

  rateLimitEnabled: boolean;
  rateLimitRps: number;
  rateLimitBurst: number;

  noveltyEnabled: boolean;
  noveltyWindowSeconds: number;
  noveltyMaxKeys: number;

  cacheSeconds: number;
  notFoundCacheSeconds: number;
  maxCacheBytes: number;
  immutable: boolean;
  staleWhileRevalidateSeconds: number;

  allowRange: boolean;
  signingSecret: string | null;

  siteName: string;
  siteTagline: string;
  blogUrl: string | null;
}

const num = (raw: string | undefined, fallback: number, min = 0, max = Number.MAX_SAFE_INTEGER): number => {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
};

const bool = (raw: string | undefined, fallback: boolean): boolean => {
  if (raw === undefined || raw.trim() === "") return fallback;
  const v = raw.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
};

const hostList = (raw: string | undefined): string[] =>
  (raw ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0 && s !== "*")
    .map((s) => s.replace(/^\./, ""));

const parse = (env: Env): FirewallConfig => {
  const allowedRefererHosts = hostList(env.ALLOWED_REFERER_HOSTS);
  const originHosts = hostList(env.ALLOWED_ORIGIN_HOSTS);

  return {
    allowedExtensions: new Set(
      (env.ALLOWED_EXTENSIONS ?? "")
        .split(",")
        .map((s) => s.trim().toLowerCase().replace(/^\./, ""))
        .filter((s) => s.length > 0),
    ),
    enforceExtension: bool(env.ENFORCE_EXTENSION, false),
    allowDotfiles: bool(env.ALLOW_DOTFILES, false),
    keyMaxLength: num(env.KEY_MAX_LENGTH, 1024, 1, 8192),
    segmentMaxLength: num(env.SEGMENT_MAX_LENGTH, 255, 1, 1024),

    hotlinkMode: (env.HOTLINK_MODE ?? "block").trim().toLowerCase() === "off" ? "off" : "block",
    hotlinkStrict: bool(env.HOTLINK_STRICT, false),
    allowedRefererHosts,
    allowedOriginHosts: originHosts.length > 0 ? originHosts : allowedRefererHosts,
    corp: (env.CORP ?? "same-site").trim().toLowerCase(),

    // 一次页面加载会并发拉几十张图，burst 必须能吞下整屏回源
    // （50 张 × 4 点 = 200 点），否则首屏会大面积 429 破图。
    rateLimitEnabled: (env.RATE_LIMIT_MODE ?? "on").trim().toLowerCase() !== "off",
    rateLimitRps: num(env.RATE_LIMIT_RPS, 40, 0.1, 10000),
    rateLimitBurst: num(env.RATE_LIMIT_BURST, 800, 1, 100000),

    noveltyEnabled: (env.NOVELTY_MODE ?? "on").trim().toLowerCase() !== "off",
    noveltyWindowSeconds: num(env.NOVELTY_WINDOW_SECONDS, 60, 1, 3600),
    noveltyMaxKeys: num(env.NOVELTY_MAX_KEYS, 600, 1, 100000),

    // 对象名形如 image.png、image-1.png，会被同名覆盖，长 TTL + immutable
    // 会让换图在缓存期内看不到，因此默认只缓存 1 小时。
    cacheSeconds: num(env.CDN_CACHE_SECONDS, 3600, 0, 31536000),
    notFoundCacheSeconds: num(env.NOT_FOUND_CACHE_SECONDS, 60, 0, 86400),
    maxCacheBytes: num(env.MAX_CACHE_BYTES, 32 * 1024 * 1024, 0, 5 * 1024 ** 4),
    immutable: bool(env.IMMUTABLE, false),
    staleWhileRevalidateSeconds: num(env.STALE_WHILE_REVALIDATE_SECONDS, 86400, 0, 604800),

    allowRange: bool(env.ALLOW_RANGE, true),
    signingSecret: (env.URL_SIGNING_SECRET ?? "").trim() || null,

    // 占位页的个人化内容：fork 的人只改这几个 vars，不用动源码
    siteName: (env.SITE_NAME ?? "").trim() || "PostPic",
    siteTagline: (env.SITE_TAGLINE ?? "").trim(),
    blogUrl: (env.BLOG_URL ?? "").trim() || null,
  };
};

let cached: { sig: string; cfg: FirewallConfig } | null = null;

/** 解析配置；vars 在同一个 isolate 内不变，按签名缓存避免每请求重复解析 */
export const getConfig = (env: Env): FirewallConfig => {
  const sig = [
    env.ALLOWED_EXTENSIONS,
    env.ENFORCE_EXTENSION,
    env.ALLOW_DOTFILES,
    env.KEY_MAX_LENGTH,
    env.SEGMENT_MAX_LENGTH,
    env.HOTLINK_MODE,
    env.HOTLINK_STRICT,
    env.ALLOWED_REFERER_HOSTS,
    env.ALLOWED_ORIGIN_HOSTS,
    env.CORP,
    env.RATE_LIMIT_MODE,
    env.RATE_LIMIT_RPS,
    env.RATE_LIMIT_BURST,
    env.NOVELTY_MODE,
    env.NOVELTY_WINDOW_SECONDS,
    env.NOVELTY_MAX_KEYS,
    env.CDN_CACHE_SECONDS,
    env.NOT_FOUND_CACHE_SECONDS,
    env.MAX_CACHE_BYTES,
    env.IMMUTABLE,
    env.STALE_WHILE_REVALIDATE_SECONDS,
    env.ALLOW_RANGE,
    // 必须用密钥本身参与签名，不能只判断"有没有"：只判断存在性时，轮换密钥
    // 前后的签名串完全相同，预热过的 isolate 会继续拿旧密钥验签——旧链接仍然
    // 有效、新链接反而 403，直到该 isolate 被回收。轮换通常正是因为怀疑泄漏。
    env.URL_SIGNING_SECRET ?? "",
    env.SITE_NAME ?? "",
    env.SITE_TAGLINE ?? "",
    env.BLOG_URL ?? "",
  ].join("\u0000");

  if (cached && cached.sig === sig) return cached.cfg;
  const cfg = parse(env);
  cached = { sig, cfg };
  return cfg;
};
