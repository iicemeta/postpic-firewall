/**
 * 扩展名 -> Content-Type。
 * 刻意不从对象自带的 httpMetadata 里取类型：桶里的元数据可能是上传时给的错值，
 * 用它等于把响应头交给上传者控制（XSS 的经典路径）。
 */
const TYPES: Record<string, string> = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  jpe: "image/jpeg",
  png: "image/png",
  webp: "image/webp",
  avif: "image/avif",
  gif: "image/gif",
  ico: "image/x-icon",
  svg: "image/svg+xml",
  bmp: "image/bmp",
  tif: "image/tiff",
  tiff: "image/tiff",
  heic: "image/heic",
  heif: "image/heif",
  jxl: "image/jxl",
  apng: "image/apng",
  mp4: "video/mp4",
  m4v: "video/x-m4v",
  webm: "video/webm",
  mov: "video/quicktime",
  mp3: "audio/mpeg",
  m4a: "audio/mp4",
  aac: "audio/aac",
  ogg: "audio/ogg",
  oga: "audio/ogg",
  opus: "audio/opus",
  wav: "audio/wav",
  flac: "audio/flac",
  pdf: "application/pdf",
  json: "application/json",
  txt: "text/plain",
  css: "text/css",
  js: "text/javascript",
  mjs: "text/javascript",
  map: "application/json",
  xml: "application/xml",
  webmanifest: "application/manifest+json",
  woff: "font/woff",
  woff2: "font/woff2",
  ttf: "font/ttf",
  otf: "font/otf",
  zip: "application/zip",
};

export const ALLOWED_EXTENSIONS_DEFAULT = Object.keys(TYPES).join(",");

export const contentTypeFor = (key: string): string => {
  const name = key.slice(key.lastIndexOf("/") + 1);
  const dot = name.lastIndexOf(".");
  if (dot <= 0) return "application/octet-stream";
  return TYPES[name.slice(dot + 1).toLowerCase()] ?? "application/octet-stream";
};

/** 能在页面里直接渲染、且不具备主动执行能力之外风险的类型 —— 这些走 inline */
const INLINE_SAFE = /^(image\/(?!svg\+xml)|video\/|audio\/|application\/pdf)/;

export const isInlineSafe = (contentType: string): boolean => INLINE_SAFE.test(contentType);

/** SVG 可以带脚本；同源内联渲染时用 CSP sandbox 把执行能力收掉 */
export const needsSandboxCsp = (contentType: string): boolean =>
  contentType === "image/svg+xml" ||
  contentType === "application/xml" ||
  contentType === "text/html" ||
  contentType === "text/xml";

export const contentDisposition = (key: string, contentType: string): string => {
  const name = key.slice(key.lastIndexOf("/") + 1) || "download";
  const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
  if (isInlineSafe(contentType)) return `inline; filename="${ascii}"`;
  const encoded = encodeURIComponent(name);
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encoded}`;
};
