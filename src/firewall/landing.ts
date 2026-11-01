import type { FirewallConfig } from "./config";

/**
 * 根路径占位页。
 *
 * 不能放进 public/：assets 绑定已移除（保留会让静态文件在 Worker 之前直出，
 * 等于绕过全部清洗）。所以页面以字符串形式内联在 Worker 里。
 *
 * 配色对齐博客的设计系统（Nuxt 站的 --hue-theme: 220deg）：
 * 主色 hsl(220 100% 55%)、页面底色 hsl(220 20% 98%)、边框 hsl(220 10% 91%)，
 * 暗色档取 hsl(220 0% 7%) / hsl(220 100% 70%)。零外部依赖——没有外链字体、
 * 没有外链图片，CSP 才能收到 default-src 'none'。
 *
 * 站点名、副标题、博客链接都来自 vars（SITE_NAME / SITE_TAGLINE / BLOG_URL），
 * 源码里不再写死任何个人内容。
 */

const CSP =
  "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/** 配置值会进 HTML，任何来源都必须转义 */
const esc = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** 只保留覆盖范围最大的主机名：父域已经包含子域，同时列出来只是噪音 */
const rootHosts = (hosts: readonly string[]): string[] =>
  hosts.filter((h) => !hosts.some((o) => o !== h && h.endsWith(`.${o}`)));

const sourceLine = (cfg: FirewallConfig): string => {
  if (cfg.hotlinkMode === "off") return "未启用来源限制";
  const hosts = rootHosts(cfg.allowedRefererHosts);
  if (hosts.length === 0) return "未启用来源限制";
  const shown = hosts.slice(0, 3).map((h) => `<code>${esc(h)}</code>`).join("、");
  const tail = hosts.length > 3 ? ` 等 ${hosts.length} 个域名引用` : " 及其子域引用";
  return `仅允许 ${shown}${tail}，外站引用会被拒绝`;
};

const blogLink = (cfg: FirewallConfig): string => {
  if (!cfg.blogUrl) return "";
  let href: string;
  try {
    const u = new URL(cfg.blogUrl);
    // 只放行 http(s)：配置里出现 javascript: 时不能把它写进 href
    if (u.protocol !== "http:" && u.protocol !== "https:") return "";
    href = u.toString();
  } catch {
    return "";
  }
  return `<a class="btn" href="${esc(href)}" rel="noopener">前往博客</a>`;
};

const render = (cfg: FirewallConfig): string => `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex">
<title>${esc(cfg.siteName)} · 图片资源服务器</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Crect width='100' height='100' rx='22' fill='%231a75ff'/%3E%3C/svg%3E">
<style>
:root{
--hue:220;
--bg:hsl(var(--hue) 0% 100%);
--bg-page:hsl(var(--hue) 20% 98%);
--border:hsl(var(--hue) 10% 91%);
--text:hsl(var(--hue) 0% 8%);
--text-2:hsl(var(--hue) 0% 44%);
--text-3:hsl(var(--hue) 0% 58%);
--primary:hsl(var(--hue) 100% 55%);
--primary-soft:hsl(var(--hue) 100% 55% / .1);
--font:"InterVariable",Inter,system-ui,-apple-system,"Noto Sans SC","Microsoft YaHei",sans-serif;
--mono:"JetBrains Mono",ui-monospace,"Cascadia Code",Consolas,monospace
}
@media (prefers-color-scheme:dark){
:root{
--bg:hsl(var(--hue) 10% 10%);
--bg-page:hsl(var(--hue) 0% 7%);
--border:hsl(var(--hue) 10% 20%);
--text:hsl(var(--hue) 0% 96%);
--text-2:hsl(var(--hue) 0% 70%);
--text-3:hsl(var(--hue) 0% 56%);
--primary:hsl(var(--hue) 100% 70%);
--primary-soft:hsl(var(--hue) 100% 70% / .16)
}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg-page);color:var(--text);font-family:var(--font);line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{width:100%;max-width:560px;min-width:0;background:var(--bg);border:1px solid var(--border);border-radius:16px;padding:40px 36px}
.mark{width:48px;height:48px;border-radius:14px;background:var(--primary-soft);color:var(--primary);display:grid;place-items:center;margin-bottom:22px}
h1{margin:0 0 6px;font-size:24px;font-weight:600;letter-spacing:-.01em}
.lead{margin:0 0 22px;font-size:14px;color:var(--text-2)}
.body{margin:0 0 26px;font-size:14px;color:var(--text-2)}
.facts{list-style:none;margin:0 0 28px;padding:0;display:grid;gap:11px}
.facts li{display:grid;grid-template-columns:60px 1fr;gap:12px;align-items:baseline;font-size:13.5px}
.k{color:var(--text);font-weight:500}
.v{color:var(--text-2);overflow-wrap:anywhere}
code{font-family:var(--mono);font-size:.94em;background:var(--primary-soft);color:var(--text);padding:1px 5px;border-radius:5px}
.btn{display:inline-block;padding:9px 18px;border-radius:10px;background:var(--primary);color:#fff;text-decoration:none;font-size:14px;font-weight:500;transition:filter .15s}
.btn:hover{filter:brightness(1.08)}
.foot{margin:26px 0 0;font-size:12px;color:var(--text-3)}
@media (max-width:480px){
.card{padding:30px 22px}
.facts{gap:14px}
.facts li{grid-template-columns:1fr;gap:4px}
}
</style>
</head>
<body>
<div class="wrap">
<main class="card">
<div class="mark" aria-hidden="true">
<svg viewBox="0 0 256 256" width="26" height="26" fill="none" stroke="currentColor" stroke-width="16" stroke-linecap="round" stroke-linejoin="round">
<rect x="32" y="48" width="192" height="160" rx="20"/>
<circle cx="92" cy="108" r="14"/>
<path d="M32 172l52-36 46 38 30-22 52 40"/>
</svg>
</div>
<h1>${esc(cfg.siteName)}</h1>
${cfg.siteTagline ? `<p class="lead">${esc(cfg.siteTagline)}</p>` : ""}
<p class="body">你打开的是一个图床，不是网站首页。这里只存放博客文章引用的图片：目录不会被列出，也不能上传文件。</p>
<ul class="facts">
<li><span class="k">只读</span><span class="v">只响应查看请求，不提供上传、删除、列目录</span></li>
<li><span class="k">限来源</span><span class="v">${sourceLine(cfg)}</span></li>
<li><span class="k">走缓存</span><span class="v">同一张图在全球边缘只回源一次，重复访问不产生费用</span></li>
</ul>
${blogLink(cfg)}
<p class="foot">postpic-firewall · Cloudflare Workers 在 R2 之前</p>
</main>
</div>
</body>
</html>`;

/**
 * 页面内容只取决于这几个配置，按它们的组合缓存渲染结果：
 * 每请求重算 4 KB 字符串并数一次 UTF-8 字节是纯浪费。
 */
let memo: { sig: string; html: string; bytes: number } | null = null;

const build = (cfg: FirewallConfig): { html: string; bytes: number } => {
  const sig = [
    cfg.siteName,
    cfg.siteTagline,
    cfg.blogUrl ?? "",
    cfg.hotlinkMode,
    cfg.allowedRefererHosts.join(","),
  ].join("\u0000");

  if (memo && memo.sig === sig) return memo;

  const html = render(cfg);
  memo = { sig, html, bytes: new TextEncoder().encode(html).length };
  return memo;
};

/**
 * 占位页响应。
 * 用 10 分钟缓存：页面本身几乎不变，但不该像图片那样长缓存，改文案后能较快生效。
 */
export const landingResponse = (isHead: boolean, firewallId: string, cfg: FirewallConfig): Response => {
  const { html, bytes } = build(cfg);
  const headers = new Headers({
    "Content-Type": "text/html; charset=utf-8",
    "Content-Length": String(bytes),
    "Cache-Control": "public, max-age=600",
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Robots-Tag": "noindex",
    "X-Firewall": firewallId,
    "X-Firewall-Cache": "BYPASS",
  });
  return new Response(isHead ? null : html, { status: 200, headers });
};
