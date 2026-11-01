# postpic-firewall

`postpic.iicemeta.com` 前面的 R2 只读防火墙。所有 `/` 下的请求先被清洗、限流、鉴权，通过后才用一个明确的键去读 R2 桶；写操作、列目录、边缘直出全部不存在。

```
client ──▶ Worker（清洗/热链/限流/验签）──▶ 边缘缓存 ──▶ R2 桶 postpic
                 │
                 └── 拦截：400/403/404/405/429（永不落到桶上）
```

## 为什么这样防"盗刷"

R2 的成本不在存储，在**操作次数**（Class B 读）和**请求量**。防火墙上每一层都在回答同一个问题：这次请求有没有必要真的触达桶？

| 威胁 | 防线 | 位置 |
| --- | --- | --- |
| 外站盗链、被当图床 | Referer 白名单 + `Cross-Origin-Resource-Policy: same-site` | `policy.ts` / `index.ts` |
| 用 `referrerPolicy=no-referrer` 把 Referer 抹掉再盗链 | `Sec-Fetch-Site: cross-site` 单独判盗链（浏览器必带） | `policy.ts` |
| 链接被复制后长期白嫖 | 可选 HMAC 签名 + `exp` 过期（最强，绕不过） | `signature.ts` |
| 同一对象被反复拉取 | 边缘缓存回填，命中后零 R2 操作 | `index.ts` 步骤 7/10 |
| `?v=随机数` 制造无限缓存未命中 | 缓存键只取归一化路径，查询串不参与 | `canonicalPath()` |
| 遍历 `image-1..image-5000`（命名可预测） | 新键配额：一分钟内见到的新键数封顶 | `novelty.ts` |
| 乱扫不存在的键 | 404 负缓存（默认 60s） | `index.ts` 步骤 8 |
| 路径穿越 `../`、`%2e%2e`、`%2f`、`\` | 单次严格解码 + 段级归一化 + 编码分隔符拦截 | `policy.ts` |
| 隐藏键、非白名单类型 | 扩展名白名单、点文件拒绝 | `policy.ts` |
| PUT/DELETE 打穿到桶 | 方法白名单，只放 GET/HEAD/OPTIONS | `index.ts` 步骤 1 |
| 单 IP 暴力刷量 | 令牌桶（缓存命中 1 点 / 回源 4 点 / Range 3 点） | `limiter.ts` |
| 上传者塞 `text/html` 借域名做 XSS | Content-Type 只按扩展名推断，忽略桶内元数据；SVG/XML 追加 CSP sandbox | `mime.ts` |
| 攻击者用日志量刷账单 | 热链/限流两类高频拦截 1/20 采样日志 | `index.ts` |

## 首屏突发：为什么 burst 是 800

博客没有懒加载，一篇文章首屏会并发拉 40-50 张图。冷缓存下每张都要回源，按回源 4 点算：

```
50 张 × 4 点 = 200 点    ← 一次首屏的瞬时开销
800 / 4      = 200 张    ← burst 能吞下的冷图数量
```

如果 burst 停在 150，第 38 张就会 429，而浏览器对破图**不会重试**，结果是静默的一排空图。所以这里把 burst 放得很宽（800），把"防刷"的职责交给下面那层。

## 新键配额：真正挡遍历的那一层

容器里的图片大多是 `image.png`、`image-1.png` 这类可预测且同名会被覆盖的命名。目录一旦暴露，遍历 `image-1..image-5000` 的成本极低，而这类请求恰好绕开了两个已有机制：每个键都是新的，边缘缓存不命中；速率可以压得很低，令牌桶不报警。

所以换一个维度计数：**同一个 IP 在一个窗口内见到多少个不同的键**。

| 行为 | 一分钟新键数 | 结果 |
| --- | --- | --- |
| 看 1 篇文章（50 张图） | 50 | 放行 |
| 连翻 10 篇 | 500 | 放行 |
| 重复看同一批图 | 0（已见过） | 放行，随便看 |
| 遍历目录 | 几千 | 撞 429 |

默认 `NOVELTY_MAX_KEYS=600`（一分钟 12 篇文章），`NOVELTY_WINDOW_SECONDS=60`。只在缓存未命中、真的要回源 R2 时才计数。

## 请求处理顺序

1. 方法白名单（GET / HEAD / OPTIONS）
2. CORS 预检（不触桶）
3. 路径 → 对象键清洗
4. Referer 热链检查
5. URL 签名校验（设了 `URL_SIGNING_SECRET` 才启用）
6. 限流
7. 边缘缓存查询 → 命中直接返回
8. 新键配额（只在未命中、真的要回源时计数）
9. 回源 R2（`head()` / `get()`，Range 与 `If-None-Match` 下推）
10. 响应加固（nosniff / CORP / CSP / Content-Disposition / ETag / 304）
11. 回填边缘缓存

拦截响应永远是小 body + `Cache-Control: no-store`，真实原因只写在 `X-Firewall-Block` 头里——排查时看这个头就知道是哪一层挡的。所有响应都带 `X-Firewall` 和 `X-Firewall-Cache`（`HIT` / `MISS` / `BYPASS`）。

## 配置

`wrangler.jsonc` 的 `vars`，全部可选：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `ALLOWED_EXTENSIONS` | 见配置 | 允许的扩展名，留空 = 不限制 |
| `ENFORCE_EXTENSION` | `false` | `true` 时无扩展名请求一律 403，可挡批量探测 |
| `ALLOW_DOTFILES` | `false` | 是否放行 `.` 开头的键 |
| `KEY_MAX_LENGTH` / `SEGMENT_MAX_LENGTH` | `1024` / `255` | 键与单段长度上限 |
| `HOTLINK_MODE` | `block` | `off` 关闭 Referer 检查 |
| `HOTLINK_STRICT` | `false` | `true` 时要求必须带 Referer 或同站 `Sec-Fetch-Site`，连 curl 这类脚本客户端一起挡 |
| `ALLOWED_REFERER_HOSTS` | `postpic.iicemeta.com,iicemeta.com` | 子域自动放行；无 Referer 且非 cross-site 放行 |
| `ALLOWED_ORIGIN_HOSTS` | 同上 | CORS 反射白名单 |
| `CORP` | `same-site` | `same-origin` / `cross-origin` / 空 = 不发 |
| `RATE_LIMIT_MODE` / `RATE_LIMIT_RPS` / `RATE_LIMIT_BURST` | `on` / `40` / `800` | 令牌桶，装的是瞬时并发 |
| `NOVELTY_MODE` / `NOVELTY_WINDOW_SECONDS` / `NOVELTY_MAX_KEYS` | `on` / `60` / `600` | 新键配额，装的是枚举 |
| `CDN_CACHE_SECONDS` | `3600` | 边缘 + 浏览器缓存时长，`0` 关闭缓存 |
| `IMMUTABLE` | `false` | 对象名带内容 hash 时才开；开了就别指望换图立刻生效 |
| `STALE_WHILE_REVALIDATE_SECONDS` | `86400` | 过期后继续供旧图、后台刷新的窗口 |
| `NOT_FOUND_CACHE_SECONDS` | `60` | 404 负缓存时长 |
| `MAX_CACHE_BYTES` | `33554432` | 超过此大小的对象不进边缘缓存，`0` = 不限制 |
| `ALLOW_RANGE` | `true` | `false` 时忽略 Range，一律整对象返回 |

密钥只走 secret：

```bash
npx wrangler secret put URL_SIGNING_SECRET
```

## 开发与验证

```bash
npm install
npm run typecheck   # tsc --noEmit
npm run dev         # wrangler dev，本地 R2 模拟
npm run deploy
```

往本地模拟桶放测试对象：

```bash
npx wrangler r2 object put postpic/smoke/hello.png --file=./x.png --local
```

## 签名链接

```bash
# Git Bash 下必须加 MSYS_NO_PATHCONV=1，否则 /a/b.png 会被改写成 C:/...
MSYS_NO_PATHCONV=1 URL_SIGNING_SECRET=xxx npm run sign -- /2026/photo.jpg --ttl 3600 --base https://postpic.iicemeta.com
# -> https://postpic.iicemeta.com/2026/photo.jpg?exp=...&sig=...
```

签名对象是**清洗后的对象键**（无前导斜杠）与 `exp` 的 HMAC-SHA256，有效期上限 30 天。启用后所有请求都必须带签名，裸链接直接 403。

## 上线注意

- `postpic.iicemeta.com` 若当前绑在 R2 桶的 Public Access 自定义域上，**先解绑**，否则 `deploy` 会报域名已被占用。解绑后公网访问只剩 Worker 一条入口，这是防火墙生效的前提。
- 本仓库已移除静态资源绑定（`assets`）：保留它会让 `public/` 下的文件在 Worker 之前被直出，等于留一条绕过清洗的通道。
- Worker 只读桶，不提供上传接口；上传仍走你自己的流程。

## 已知边界

- 限流与新键配额都是 **isolate 内存级**：N 个 isolate 就有 N 倍预算，冷启动会重置。挡单点刷量够用，扛不住分布式换 IP。要硬上限请叠加 Cloudflare WAF 速率规则（按 `ip` + `http.request.uri.path`）。
- 默认只缓存 1 小时，是"换图要及时生效"和"少回源"之间的折中。因为对象名 `image.png` 会被同名覆盖，上了 immutable + 长 TTL 就等于换图要等一周。彻底解法是让文件名带内容 hash（`image-<hash>.png`），然后 `IMMUTABLE=true` + `CDN_CACHE_SECONDS=31536000`，可以做到永不回源。
- 缓存过期后由 `stale-while-revalidate` 兜着：期间继续发旧图、后台回源刷新，避免图集页同时过期时把 R2 打出一波尖峰。
- Range 请求不走边缘缓存，只做限流加权（每次 3 点）。纯图站建议 `ALLOW_RANGE=false`，让重复读全部落在缓存上。
- 无 Referer 且 `Sec-Fetch-Site: cross-site` 才判盗链。要连"不带任何浏览器头"的脚本客户端一起挡，打开 `HOTLINK_STRICT`——代价是 wget / RSS 阅读器 / 图片代理全部 403。
