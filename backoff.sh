#!/usr/bin/env bash
# Verify retry/backoff honours Retry-After and gives up cleanly.
set +e
cd "$(dirname "$0")/.." || exit 1
export CFDNS_NO_BANNER=1 CFDNS_ROOT=/tmp/bo-root CF_API_TOKEN=dummy CFDNS_MAX_RETRY=3
rm -rf /tmp/bo-root
. test/lib/load.sh
load_modules "$PWD" core/http.sh
jq_set "$CFDNS_CONFIG" '.token_backend = "env"'

# local server on an ephemeral port: 429 + Retry-After twice, then 200
export PORTFILE="$(mktemp)"
python3 - <<'PY' &
import http.server, json
n = {'i':0}
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        n['i'] += 1
        if n['i'] <= 2:
            self.send_response(429); self.send_header('Retry-After','1')
            self.send_header('Content-Type','application/json'); self.end_headers()
            self.wfile.write(b'{"success":false,"errors":[{"code":10000,"message":"rate limited"}]}')
        else:
            self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
            self.wfile.write(json.dumps({"success":True,"result":{"attempt":n['i']}}).encode())
    def log_message(self,*a): pass
import os
srv=http.server.HTTPServer(('127.0.0.1',0), H)
open(os.environ['PORTFILE'],'w').write(str(srv.server_address[1]))
srv.serve_forever()
PY
SRV=$!
for _ in $(seq 1 50); do [ -s "$PORTFILE" ] && break; sleep 0.1; done
PORT="$(cat "$PORTFILE")"
[ -n "$PORT" ] || { echo "BACKOFF TEST FAILED (server did not start)"; kill $SRV 2>/dev/null; exit 1; }
CF_API="http://127.0.0.1:$PORT"
echo "--- expect 2 retries then success ---"
t0=$(date +%s)
out="$(cf_api GET "/x")"
t1=$(date +%s)
echo "response: $out"
echo "elapsed: $((t1-t0))s (should be >=2s from two Retry-After:1 waits)"
rc=0
if echo "$out" | grep -qE '"success": ?true'; then echo "BACKOFF TEST PASS"; else echo "BACKOFF TEST FAILED"; rc=1; fi
if [ $((t1-t0)) -lt 2 ]; then echo "BACKOFF TEST FAILED (Retry-After not honoured)"; rc=1; fi
kill $SRV 2>/dev/null
rm -f "$PORTFILE"
exit $rc
