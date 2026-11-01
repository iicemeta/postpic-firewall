#!/usr/bin/env bash
# 防火墙回归矩阵。先造对象再跑：
#   npx wrangler r2 object put postpic/smoke/hello.png --file=./x.png --local
#   npx wrangler r2 object put postpic/smoke/three.png --file=./x.png --local
#   npm run dev &
#   BASE=http://127.0.0.1:8788 bash scripts/smoke.sh
#
# 加 --bench 追加并发压测（验证令牌桶，需要 node ≥ 18 的 fetch）。
set -u

BASE="${BASE:-http://127.0.0.1:8788}"
ASSET="${ASSET:-/smoke/hello.png}"
PASS=0
FAIL=0

status_of() { curl -s -o /dev/null -w "%{http_code}" "$@" 2>/dev/null; }
header_of() { curl -s -o /dev/null -D - "$@" 2>/dev/null | tr -d '\r'; }

check() { # name expect_status [curl args...]
  local name="$1" expect="$2"; shift 2
  local status reason
  local dump
  dump=$(header_of "$@")
  status=$(printf '%s' "$dump" | head -1 | awk '{print $2}')
  reason=$(printf '%s' "$dump" | grep -i '^x-firewall-block:' | awk '{print $2}')
  if [ "$status" = "$expect" ]; then
    PASS=$((PASS + 1)); printf 'PASS  %-46s %s %s\n' "$name" "$status" "$reason"
  else
    FAIL=$((FAIL + 1)); printf 'FAIL  %-46s got=%s want=%s %s\n' "$name" "$status" "$expect" "$reason"
  fi
}

ETAG=$(header_of "$BASE$ASSET" | grep -i '^etag:' | sed 's/^[Ee][Tt]ag: //')
if [ -z "$ETAG" ]; then
  echo "取不到 ETag：确认 $BASE$ASSET 可访问（对象是否已写入本地桶？）"
  exit 1
fi

echo "--- 正常路径 ---"
check "GET 正常对象"                    200 "$BASE$ASSET"
check "二次命中缓存"                    200 "$BASE$ASSET"
check "HEAD 正常对象"                   200 -I "$BASE$ASSET"
check "304 条件请求"                    304 -H "If-None-Match: $ETAG" "$BASE$ASSET"
check "重复斜杠归一化"                  200 "$BASE//smoke///hello.png"
check "点段归一化"                      200 "$BASE/smoke/./hello.png"
check "不同查询串同享缓存键"             200 "$BASE$ASSET?cb=9f2a1b"

echo "--- 路径穿越 / 编码绕过 ---"
check "根路径无键"                      404 "$BASE/"
check "裸 ../ 归一化后仍在桶内"          404 --path-as-is "$BASE/../secret.png"
check "路径内 ../ 归一化"               404 --path-as-is "$BASE/smoke/../../secret.png"
check "%2e%2e 归一化"                   404 --path-as-is "$BASE/smoke/%2e%2e/hello.png"
check "解不掉的 ..%2f"                  400 --path-as-is "$BASE/smoke/..%2fsecret.png"
check "%2f 编码分隔符"                  400 --path-as-is "$BASE/smoke%2fhello.png"
check "%5c 编码反斜杠"                  400 --path-as-is "$BASE/smoke%5chello.png"
check "双重编码穿越"                    400 --path-as-is "$BASE/smoke/%252e%252e/hello.png"
check "残缺百分号转义"                  400 --path-as-is "$BASE/smoke/%zz.png"
check "空字节"                          400 --path-as-is "$BASE$ASSET%00.png"

echo "--- 键策略 ---"
check "隐藏文件 .env"                   403 "$BASE/.env"
check "非白名单扩展 .php"               403 "$BASE/smoke/hello.php"

echo "--- 热链 ---"
check "外站 Referer"                    403 -H "Referer: https://evil.example/x" "$BASE$ASSET"
check "后缀伪装 Referer"                403 -H "Referer: https://iicemeta.com.evil.example/" "$BASE$ASSET"
check "子域 Referer 放行"               200 -H "Referer: https://blog.iicemeta.com/post" "$BASE$ASSET"
check "同域 Referer 放行"               200 -H "Referer: https://postpic.iicemeta.com/" "$BASE$ASSET"
check "无 Referer 直连放行"             200 "$BASE$ASSET"

echo "--- 方法 ---"
check "POST 拒绝"                       405 -X POST "$BASE$ASSET"
check "PUT 拒绝"                        405 -X PUT --data x "$BASE$ASSET"
check "DELETE 拒绝"                     405 -X DELETE "$BASE$ASSET"
check "PROPFIND 拒绝"                   405 -X PROPFIND "$BASE$ASSET"

echo "--- CORS ---"
check "白名单 Origin 预检"              204 -X OPTIONS -H "Origin: https://iicemeta.com" "$BASE$ASSET"
check "非白名单 Origin 预检"            403 -X OPTIONS -H "Origin: https://evil.example" "$BASE$ASSET"

echo "--- 404 负缓存 ---"
check "不存在的键"                      404 "$BASE/smoke/nope.png"
check "不存在键二次请求"                 404 "$BASE/smoke/nope.png"

echo
echo "PASS=$PASS FAIL=$FAIL"

if [ "${1:-}" = "--bench" ]; then
  echo
  echo "--- 并发压测 300 次（burst / rps 见 vars）---"
  node -e '
    const n = 300, url = process.argv[1], t0 = Date.now();
    Promise.all(Array.from({ length: n }, () => fetch(url).then((r) => r.status)))
      .then((s) => {
        const c = s.reduce((a, x) => ((a[x] = (a[x] || 0) + 1), a), {});
        console.log("elapsed_ms", Date.now() - t0, JSON.stringify(c));
      });
  ' "$BASE$ASSET"
fi

[ "$FAIL" -eq 0 ] || exit 1
