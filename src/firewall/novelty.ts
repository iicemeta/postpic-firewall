/**
 * 新键配额 —— 针对"可预测命名"的闸门。
 *
 * 桶里的图片大多叫 image.png / image-1.png，目录一旦暴露，遍历 image-1..image-5000
 * 的成本极低。令牌桶此时帮不上忙：它是按请求量算的，而枚举恰好可以用很低的速率
 * 持续敲，每个新键都穿透缓存直达 R2。
 *
 * 所以这里换一个维度计数：同一个 IP 在一个窗口内"见过多少个不同的键"。
 * - 重复看同一批图 → 键已见过，不计数，随便看
 * - 翻文章 → 一篇几十个新键，一分钟翻十几篇也就几百
 * - 遍历目录 → 一分钟几千上万，直接撞墙
 *
 * 内存是 isolate 级的，条目上限 MAX_TRACKED_IPS 兜底；超限按插入顺序淘汰最旧的，
 * 宁可少挡一点也不能让限流器自己变成故障源。
 */
interface NoveltyWindow {
  start: number;
  /** 已见过的对象键哈希（FNV-1a 32bit），碰撞只会导致多放行，不会误拦 */
  keys: Set<number>;
}

const windows = new Map<string, NoveltyWindow>();
const MAX_TRACKED_IPS = 1000;

const fnv1a = (s: string): number => {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
};

const evict = (now: number, windowMs: number): void => {
  for (const [ip, w] of windows) {
    if (now - w.start >= windowMs) windows.delete(ip);
  }
  while (windows.size >= MAX_TRACKED_IPS) {
    const oldest = windows.keys().next();
    if (oldest.done) break;
    windows.delete(oldest.value);
  }
};

/**
 * 记录一个对象键。返回 true 表示放行。
 * 只在"真的要回源 R2"时调用——边缘缓存命中不消耗配额。
 */
export const takeNovelty = (
  identifier: string,
  objectKey: string,
  windowMs: number,
  quota: number,
): boolean => {
  const now = Date.now();

  let w = windows.get(identifier);
  if (!w || now - w.start >= windowMs) {
    if (!w && windows.size >= MAX_TRACKED_IPS) evict(now, windowMs);
    w = { start: now, keys: new Set() };
    windows.set(identifier, w);
  }

  const hash = fnv1a(objectKey);
  if (w.keys.has(hash)) return true;
  if (w.keys.size >= quota) return false;
  w.keys.add(hash);
  return true;
};

/** 暴露给测试用 */
export const __resetNovelty = (): void => windows.clear();
