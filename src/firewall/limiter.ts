/**
 * 令牌桶限流。
 *
 * 这是 isolate 内存级、best-effort 的限流：全球 N 个 isolate 就有 N 倍预算。
 * 它挡的是单点暴力刷量（把 R2 Class B 操作费和 Worker 请求数打爆），
 * 而不是替代平台级防护。硬上限请叠加 Cloudflare WAF 速率规则。
 */
interface Bucket {
  tokens: number;
  /** 上次填充时间（ms） */
  ts: number;
}

const buckets = new Map<string, Bucket>();
const MAX_ENTRIES = 20000;
const IDLE_MS = 120_000;

const sweep = (now: number): void => {
  for (const [key, b] of buckets) {
    if (now - b.ts > IDLE_MS) buckets.delete(key);
  }
  // 极端情况下仍然超限就直接清空：限流器自身绝不能成为故障源（fail-open）
  if (buckets.size > MAX_ENTRIES) buckets.clear();
};

export interface Limits {
  rps: number;
  burst: number;
}

/**
 * 消耗令牌。返回 true 表示放行。
 *
 * cost 是调用方按路径算好的：入口统一扣 1；只有"GET + 无 Range + 边缘缓存未命中"
 * 会在回源前再扣 3（合计 4）。HEAD 与 Range 不进缓存分支，因此始终只扣 1。
 */
export const takeToken = (identifier: string, cost: number, limits: Limits): boolean => {
  const now = Date.now();

  if (buckets.size > MAX_ENTRIES / 2) sweep(now);

  let bucket = buckets.get(identifier);
  if (!bucket) {
    bucket = { tokens: limits.burst, ts: now };
    buckets.set(identifier, bucket);
  } else {
    const elapsed = Math.max(0, now - bucket.ts) / 1000;
    bucket.tokens = Math.min(limits.burst, bucket.tokens + elapsed * limits.rps);
    bucket.ts = now;
  }

  const need = Math.min(cost, limits.burst);
  if (bucket.tokens < need) return false;
  bucket.tokens -= need;
  return true;
};

/** 暴露给测试用 */
export const __resetLimiter = (): void => buckets.clear();
