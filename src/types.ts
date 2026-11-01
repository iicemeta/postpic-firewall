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

  // ---- 缓存 ----
  CDN_CACHE_SECONDS?: string;
  NOT_FOUND_CACHE_SECONDS?: string;
  /** 超过该字节数不进边缘缓存（0 = 不限制） */
  MAX_CACHE_BYTES?: string;

  // ---- 其他 ----
  ALLOW_RANGE?: string;
  /** 设置后强制校验 URL 签名（HMAC-SHA256），未设置则不校验 */
  URL_SIGNING_SECRET?: string;
}
