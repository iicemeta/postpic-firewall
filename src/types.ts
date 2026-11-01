/**
 * Worker 运行时绑定与环境变量。
 * 变量全部为字符串（wrangler `vars` / secrets），由 firewall/config.ts 解析并给默认值。
 */
export interface Env {
  /** R2 绑定，wrangler.jsonc 中 `r2_buckets[].binding` */
  BUCKET: R2Bucket;

  // ---- 键策略 ----
  /** 允许的扩展名，逗号分隔，空字符串=不限制 */
  ALLOWED_EXTENSIONS?: string;
  /** 是否要求必须有扩展名（true 时无扩展名请求一律 403，可挡批量探测） */
  ENFORCE_EXTENSION?: string;
  /** 键最大总长度 */
  KEY_MAX_LENGTH?: string;
  /** 单段最大长度 */
  SEGMENT_MAX_LENGTH?: string;
  /** 是否允许以点开头的隐藏键 */
  ALLOW_DOTFILES?: string;

  // ---- 热链防护 ----
  /** block | off */
  HOTLINK_MODE?: string;
  /** 允许的 Referer 主机名，逗号分隔（子域自动放行） */
  ALLOWED_REFERER_HOSTS?: string;
  /** CORS 反射白名单，逗号分隔，留空=沿用 Referer 白名单 */
  ALLOWED_ORIGIN_HOSTS?: string;
  /** Cross-Origin-Resource-Policy: same-site | same-origin | cross-origin | "" (省略) */
  CORP?: string;

  // ---- 限流（单 isolate 令牌桶，best-effort）----
  RATE_LIMIT_RPS?: string;
  RATE_LIMIT_BURST?: string;
  /** off 关闭限流 */
  RATE_LIMIT_MODE?: string;

  // ---- 新键配额：只限制"一分钟见到多少不同对象"，放过重复访问 ----
  /** off 关闭 */
  NOVELTY_MODE?: string;
  NOVELTY_WINDOW_SECONDS?: string;
  NOVELTY_MAX_KEYS?: string;

  // ---- 缓存 ----
  CDN_CACHE_SECONDS?: string;
  NOT_FOUND_CACHE_SECONDS?: string;
  /** 超过该字节数不进边缘缓存（0 = 不限制） */
  MAX_CACHE_BYTES?: string;
  /** 对象名带内容 hash 时可开：加 immutable，省掉重验证 */
  IMMUTABLE?: string;
  /** 非 immutable 时的 stale-while-revalidate / stale-if-error 秒数 */
  STALE_WHILE_REVALIDATE_SECONDS?: string;

  // ---- 根路径占位页 ----
  /** 页面标题里的站点名，默认 PostPic */
  SITE_NAME?: string;
  /** 标题下的一句话说明，留空则不显示该行 */
  SITE_TAGLINE?: string;
  /** 「前往博客」按钮的目标地址，留空则不显示按钮；只接受 http(s) */
  BLOG_URL?: string;

  // ---- 其他 ----
  ALLOW_RANGE?: string;
  /** strict 时要求请求必须带 Referer 或同站 Sec-Fetch-Site，否则视为盗链 */
  HOTLINK_STRICT?: string;
  /** 设置后强制校验 URL 签名（HMAC-SHA256），未设置则不校验 */
  URL_SIGNING_SECRET?: string;
}
