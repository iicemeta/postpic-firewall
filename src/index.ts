import { Hono } from "hono";
import type { Env } from "./types";
import { getConfig, type FirewallConfig } from "./firewall/config";
import { checkReferer, originAllowed, resolveObjectKey, type Block } from "./firewall/policy";
import { takeToken } from "./firewall/limiter";
import { takeNovelty } from "./firewall/novelty";
import { verifySignature } from "./firewall/signature";
import { contentDisposition, contentTypeFor, needsSandboxCsp } from "./firewall/mime";
import { landingResponse } from "./firewall/landing";

const FIREWALL_ID = "postpic-firewall/1";
const ALLOWED_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** 根路径与 /index.html 走占位页，不读桶（桶里没有 html，扩展名白名单也不放行） */
const ROOT_PATH = /^\/+$|^\/index\.html?$/i;
const SANDBOX_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

/**
 * 边缘缓存键的纪元号。
 *
 * caches.default 就是 Cloudflare 边缘缓存本体：R2 走自定义域直连的时期，图片已经
 * 被缓进这一层，头是 R2 的默认值（max-age=14400、没有任何加固头）。Worker 上线后
 * 用同一个键去 match，会把这些旧条目当成自己的缓存命中，于是 nosniff /
 * Content-Disposition / CSP 全部丢失，浏览器还会按 4 小时缓存旧图。
 *
 * 加一个前缀把纪元隔开：新代码只认 /__fw-v1/ 下的条目，旧条目让它自己过期。
 * 前缀拼接在 canonicalPath 之前，真实对象无论如何都撞不上这个键。
 */
const CACHE_EPOCH = "v1";

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
const notModified = (source: Headers, cacheState: string, cacheControl?: string): Response => {
  const headers = new Headers(source);
  headers.delete("Content-Type");
  headers.delete("Content-Disposition");
  headers.delete("Content-Length");
  headers.set("X-Firewall-Cache", cacheState);
  if (cacheControl) headers.set("Cache-Control", cacheControl);
  return new Response(null, { status: 304, headers });
};

const applyCors = (headers: Headers, origin: string | null, cfg: FirewallConfig): void => {
  if (!origin || !originAllowed(origin, cfg)) return;
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Vary", "Origin");
};

/**
 * 缓存策略。桶里的对象名是 image.png、image-1.png 这种可预测且会被同名覆盖的写法，
 * 长 TTL + immutable 会让换图在缓存期内一直看不到，所以默认只给 1 小时，
 * 再用 stale-while-revalidate 让过期后的高并发请求继续吃旧图、不被回源阻塞。
 * 对象名带内容 hash 时把 IMMUTABLE 打开，才适合上 immutable + 超长 TTL。
 */
const cacheControlFor = (cfg: FirewallConfig, noStore: boolean): string => {
  if (noStore || cfg.cacheSeconds === 0) return "no-store";
  const base = `public, max-age=${cfg.cacheSeconds}`;
  if (cfg.immutable) return `${base}, immutable`;
  if (cfg.staleWhileRevalidateSeconds > 0) {
    return `${base}, stale-while-revalidate=${cfg.staleWhileRevalidateSeconds}, stale-if-error=${cfg.staleWhileRevalidateSeconds}`;
  }
  return base;
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

  // ---- 2.5 根路径占位页：不进 R2、不写缓存 ----
  // 放在路径清洗之前，因为 "/" 归一化后本来就是 empty_key。占位页是公开说明页，
  // 不参与热链检查，但仍然计入限流（被刷的时候一样要挡住）。
  if (ROOT_PATH.test(url.pathname)) {
    const landingIp = clientIp(req);
    if (
      cfg.rateLimitEnabled &&
      !takeToken(`ip:${landingIp}`, 1, { rps: cfg.rateLimitRps, burst: cfg.rateLimitBurst })
    ) {
      return deny({ reason: "rate_limited", status: 429 }, url, req, { "Retry-After": "1" });
    }
    return landingResponse(req.method === "HEAD", FIREWALL_ID, cfg);
  }

  // ---- 3. 路径清洗 -> 对象键 ----
  const resolved = resolveObjectKey(url.pathname, cfg);
  if (!resolved.ok) return deny(resolved.block, url, req);
  const key = resolved.key;

  // ---- 4. 热链防护 ----
  const refererBlock = checkReferer(req.headers, host, cfg);
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
  const cacheUrl = `https://${host}/__fw-${CACHE_EPOCH}${canonicalPath(key)}`;
  const headers = new Headers({ "X-Firewall": FIREWALL_ID });

  // ---- 7. 边缘缓存：同一对象只回源一次，重复请求不再产生 R2 操作 ----
  if (!range && !isHead) {
    const hit = await caches.default.match(cacheUrl);
    if (hit) {
      // 缓存副本的 Cache-Control 已被 zone 的 Browser Cache TTL 改写成别的值
      // （实测 3600 进、14400 出），这里按配置重新盖回，保证浏览器端看到的
      // TTL 与 CDN_CACHE_SECONDS 一致，换图后不会被拖到 4 小时才更新。
      const hitCacheControl = cacheControlFor(cfg, false);
      const hitEtag = hit.headers.get("ETag");
      if (hitEtag && etagMatches(req.headers.get("if-none-match"), hitEtag)) {
        return notModified(hit.headers, "HIT", hitCacheControl);
      }
      return rebuild(hit, (h) => {
        h.set("X-Firewall-Cache", "HIT");
        h.set("Cache-Control", hitCacheControl);
        applyCors(h, origin, cfg);
      });
    }
    // 回源成本更高，额外扣预算（缓存命中只算 1）
    if (cfg.rateLimitEnabled && !takeToken(`ip:${ip}`, 3, limits)) {
      return deny({ reason: "rate_limited", status: 429 }, url, req, { "Retry-After": "1" });
    }
  }

  // ---- 7.5 新键配额：走到这里说明缓存没命中，这次回源会真的花 R2 操作 ----
  // 计数维度是"一分钟内见过多少个不同键"，所以正常翻文章不受影响，遍历目录会撞墙。
  if (
    cfg.noveltyEnabled &&
    !takeNovelty(`ip:${ip}`, key, cfg.noveltyWindowSeconds * 1000, cfg.noveltyMaxKeys)
  ) {
    return deny({ reason: "novelty_quota", status: 429 }, url, req, {
      "Retry-After": String(cfg.noveltyWindowSeconds),
    });
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
    } else if (req.headers.get("if-none-match")) {
      // 把客户端的 If-None-Match 下推给 R2：未变更时只回元数据，不传 body。
      // 浏览器重复访问同一张图时，这一条能省掉整份 egress。
      const cond = new Headers();
      cond.set("if-none-match", req.headers.get("if-none-match") as string);
      obj = await c.env.BUCKET.get(key, { onlyIf: cond });
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
  // 只有 GET 且下推了 If-None-Match 时，"没有 body"才意味着未变更；
  // HEAD 走的 head() 本来就不带 body，不能当成 304。
  const upstreamNotModified =
    !isHead && !range && req.headers.get("if-none-match") !== null && typeof (obj as R2ObjectBody).body === "undefined";

  headers.set("ETag", etag);
  headers.set("Last-Modified", new Date(obj.uploaded).toUTCString());
  headers.set("Accept-Ranges", cfg.allowRange ? "bytes" : "none");
  headers.set("Cache-Control", cacheControlFor(cfg, range !== null));
  if (cfg.corp) headers.set("Cross-Origin-Resource-Policy", cfg.corp);

  // 条件请求：命中就 304，连 body 都不生成
  if (upstreamNotModified || (!range && etagMatches(req.headers.get("if-none-match"), etag))) {
    return notModified(headers, "MISS");
  }

  headers.set("Content-Type", contentType);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Content-Disposition", contentDisposition(key, contentType));
  if (needsSandboxCsp(contentType)) headers.set("Content-Security-Policy", SANDBOX_CSP);

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
