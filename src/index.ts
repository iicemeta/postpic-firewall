import { Hono } from "hono";
import type { Env } from "./types";
import { getConfig, type FirewallConfig } from "./firewall/config";
import { checkReferer, originAllowed, resolveObjectKey, type Block } from "./firewall/policy";
import { takeToken } from "./firewall/limiter";
import { verifySignature } from "./firewall/signature";
import { contentDisposition, contentTypeFor, needsSandboxCsp } from "./firewall/mime";

const FIREWALL_ID = "postpic-firewall/1";
const ALLOWED_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const SANDBOX_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

const app = new Hono<{ Bindings: Env }>();

const clientIp = (req: Request): string =>
  req.headers.get("cf-connecting-ip") ?? req.headers.get("x-real-ip") ?? "0.0.0.0";

const BODY_FOR: Record<number, string> = {
  400: "Bad Request",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  416: "Range Not Satisfiable",
  429: "Too Many Requests",
  502: "Bad Gateway",
};

/** 拦截响应：极小 body、no-store、只把原因放进头里，不向外面泄漏规则细节 */
const blocked = (block: Block, extra?: Record<string, string>): Response => {
  const headers = new Headers({
    "Content-Type": "text/plain; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Firewall": FIREWALL_ID,
    "X-Firewall-Block": block.reason,
  });
  if (block.status === 405) headers.set("Allow", "GET, HEAD, OPTIONS");
  if (extra) for (const [k, v] of Object.entries(extra)) headers.set(k, v);
  return new Response(BODY_FOR[block.status] ?? "Blocked", { status: block.status, headers });
};

/** 命中率高的拦截原因（热链、限流）做采样日志，避免攻击者把日志量变成账单 */
const SAMPLED_REASONS = new Set(["hotlink", "rate_limited"]);
let logBudget = 0;

const logBlock = (block: Block, url: URL, req: Request): void => {
  if (SAMPLED_REASONS.has(block.reason)) {
    logBudget += 1;
    if (logBudget % 20 !== 1) return;
  }
  console.log(
    JSON.stringify({
      event: "fw.block",
      reason: block.reason,
      status: block.status,
      method: req.method,
      host: url.hostname,
      path: url.pathname.slice(0, 300),
      ip: clientIp(req),
      ua: (req.headers.get("user-agent") ?? "").slice(0, 120),
      referer: (req.headers.get("referer") ?? "").slice(0, 200),
    }),
  );
};

const deny = (block: Block, url: URL, req: Request, extra?: Record<string, string>): Response => {
  logBlock(block, url, req);
  return blocked(block, extra);
};

const rebuild = (res: Response, mutate: (headers: Headers) => void): Response => {
  const headers = new Headers(res.headers);
  mutate(headers);
  const nullBody = res.status === 204 || res.status === 205 || res.status === 304;
  return new Response(nullBody ? null : res.body, {
    status: res.status,
    statusText: res.statusText,
    headers,
  });
};

/** 304：只回校验器，body 与 entity 头一律去掉 */
const notModified = (source: Headers, cacheState: string): Response => {
  const headers = new Headers(source);
  headers.delete("Content-Type");
  headers.delete("Content-Disposition");
  headers.delete("Content-Length");
  headers.set("X-Firewall-Cache", cacheState);
  return new Response(null, { status: 304, headers });
};

const applyCors = (headers: Headers, origin: string | null, cfg: FirewallConfig): void => {
  if (!origin || !originAllowed(origin, cfg)) return;
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Vary", "Origin");
};

/** If-None-Match 匹配（弱比较：忽略 W/ 前缀） */
const etagMatches = (header: string | null, etag: string): boolean => {
  if (!header) return false;
  const trimmed = header.trim();
  if (trimmed === "*") return true;
  const target = etag.replace(/^W\//, "");
  return trimmed
    .split(",")
    .map((s) => s.trim().replace(/^W\//, ""))
    .includes(target);
};

const canonicalPath = (key: string): string => `/${key.split("/").map(encodeURIComponent).join("/")}`;

/**
 * R2 返回的 range 可能是 offset/length、单边 length、suffix 三种形状，本地运行时
 * 对整对象读取还会给出一个字段全空的 range 对象，因此这里全部按"缺省即整对象"处理。
 */
const resolveRange = (r: R2Range | undefined, size: number): { start: number; length: number } => {
  if (!r) return { start: 0, length: size };

  if ("suffix" in r && typeof r.suffix === "number") {
    const length = Math.min(r.suffix, size);
    return { start: Math.max(0, size - length), length };
  }

  const offset = typeof (r as { offset?: number }).offset === "number" ? (r as { offset: number }).offset : null;
  const len = typeof (r as { length?: number }).length === "number" ? (r as { length: number }).length : null;

  if (offset === null && len === null) return { start: 0, length: size };
  if (offset === null) {
    const length = Math.min(len as number, size);
    return { start: Math.max(0, size - length), length };
  }
  return { start: offset, length: len ?? Math.max(0, size - offset) };
};

app.all("*", async (c) => {
  const cfg = getConfig(c.env);
  const req = c.req.raw;
  const url = new URL(req.url);
  const host = url.hostname.toLowerCase();

  // ---- 1. 方法白名单：写操作永远不落到桶上 ----
  if (!ALLOWED_METHODS.has(req.method)) {
    return deny({ reason: "method_not_allowed", status: 405 }, url, req);
  }

  const origin = req.headers.get("origin");

  // ---- 2. CORS 预检，不触碰桶 ----
  if (req.method === "OPTIONS") {
    if (!originAllowed(origin, cfg)) {
      return deny({ reason: "hotlink", status: 403 }, url, req);
    }
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": origin as string,
        "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
        "Access-Control-Max-Age": "86400",
        "X-Firewall": FIREWALL_ID,
        "Cache-Control": "no-store",
      },
    });
  }

  // ---- 3. 路径清洗 -> 对象键 ----
  const resolved = resolveObjectKey(url.pathname, cfg);
  if (!resolved.ok) return deny(resolved.block, url, req);
  const key = resolved.key;

  // ---- 4. 热链防护 ----
  const refererBlock = checkReferer(req.headers.get("referer"), host, cfg);
  if (refererBlock) return deny(refererBlock, url, req);

  // ---- 5. URL 签名（可选但最强）----
  if (cfg.signingSecret) {
    const ok = await verifySignature(
      key,
      url.searchParams.get("exp"),
      url.searchParams.get("sig"),
      cfg.signingSecret,
    );
    if (!ok) return deny({ reason: "bad_signature", status: 403 }, url, req);
  }

  // ---- 6. 限流 ----
  const ip = clientIp(req);
  const limits = { rps: cfg.rateLimitRps, burst: cfg.rateLimitBurst };
  if (cfg.rateLimitEnabled && !takeToken(`ip:${ip}`, 1, limits)) {
    return deny({ reason: "rate_limited", status: 429 }, url, req, { "Retry-After": "1" });
  }

  const isHead = req.method === "HEAD";
  const range = cfg.allowRange ? req.headers.get("range") : null;
  const cacheUrl = `https://${host}${canonicalPath(key)}`;
  const headers = new Headers({ "X-Firewall": FIREWALL_ID });

  // ---- 7. 边缘缓存：同一对象只回源一次，重复请求不再产生 R2 操作 ----
  if (!range && !isHead) {
    const hit = await caches.default.match(cacheUrl);
    if (hit) {
      const hitEtag = hit.headers.get("ETag");
      if (hitEtag && etagMatches(req.headers.get("if-none-match"), hitEtag)) {
        return notModified(hit.headers, "HIT");
      }
      return rebuild(hit, (h) => {
        h.set("X-Firewall-Cache", "HIT");
        applyCors(h, origin, cfg);
      });
    }
    // 回源成本更高，额外扣预算（缓存命中只算 1）
    if (cfg.rateLimitEnabled && !takeToken(`ip:${ip}`, 3, limits)) {
      return deny({ reason: "rate_limited", status: 429 }, url, req, { "Retry-After": "1" });
    }
  }

  // ---- 8. 回源 R2 ----
  let obj: R2Object | R2ObjectBody | null;
  try {
    if (isHead) {
      obj = await c.env.BUCKET.head(key);
    } else if (range) {
      const only = new Headers();
      only.set("range", range);
      obj = await c.env.BUCKET.get(key, { range: only });
    } else {
      obj = await c.env.BUCKET.get(key);
    }
  } catch {
    return range
      ? deny({ reason: "range_invalid", status: 416 }, url, req)
      : deny({ reason: "upstream_error", status: 502 }, url, req);
  }

  if (!obj) {
    headers.set("Content-Type", "text/plain; charset=utf-8");
    headers.set("Cache-Control", `public, max-age=${cfg.notFoundCacheSeconds}`);
    headers.set("X-Firewall-Cache", "MISS");
    const notFound = new Response("Not Found", { status: 404, headers });
    // 负缓存：枚举不存在的键不再穿透到 R2（配合限流把扫描成本压到零）
    if (cfg.notFoundCacheSeconds > 0 && !range && !isHead) {
      c.executionCtx.waitUntil(caches.default.put(cacheUrl, notFound.clone()));
    }
    return notFound;
  }

  // ---- 9. 组装响应 ----
  const contentType = contentTypeFor(key);
  const etag = obj.httpEtag || `"${obj.etag}"`;

  headers.set("Content-Type", contentType);
  headers.set("ETag", etag);
  headers.set("Last-Modified", new Date(obj.uploaded).toUTCString());
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Content-Disposition", contentDisposition(key, contentType));
  headers.set("Accept-Ranges", cfg.allowRange ? "bytes" : "none");
  if (cfg.corp) headers.set("Cross-Origin-Resource-Policy", cfg.corp);
  if (needsSandboxCsp(contentType)) headers.set("Content-Security-Policy", SANDBOX_CSP);
  headers.set(
    "Cache-Control",
    range || cfg.cacheSeconds === 0
      ? "no-store"
      : `public, max-age=${cfg.cacheSeconds}, immutable`,
  );

  // 条件请求：命中就 304，连 body 都不生成
  if (!range && etagMatches(req.headers.get("if-none-match"), etag)) {
    return notModified(headers, "MISS");
  }

  // Range 分片：不写边缘缓存，避免一份对象被上千个不同区间反复回源
  if (range) {
    const { start, length } = resolveRange(obj.range, obj.size);
    const end = Math.max(start, start + length - 1);
    headers.set("Content-Range", `bytes ${start}-${end}/${obj.size}`);
    headers.set("Content-Length", String(length));
    headers.set("X-Firewall-Cache", "BYPASS");
    applyCors(headers, origin, cfg);
    return new Response((obj as R2ObjectBody).body, { status: 206, headers });
  }

  headers.set("Content-Length", String(obj.size));
  headers.set("X-Firewall-Cache", "MISS");

  if (isHead) {
    applyCors(headers, origin, cfg);
    return new Response(null, { status: 200, headers });
  }

  const res = new Response((obj as R2ObjectBody).body, { status: 200, headers });

  // ---- 10. 回填边缘缓存（此处的头不含 CORS，避免把首个请求者的 Origin 固化进缓存）----
  if (cfg.cacheSeconds > 0 && (cfg.maxCacheBytes === 0 || obj.size <= cfg.maxCacheBytes)) {
    c.executionCtx.waitUntil(caches.default.put(cacheUrl, res.clone()));
  }

  return rebuild(res, (h) => applyCors(h, origin, cfg));
});

export default app;
