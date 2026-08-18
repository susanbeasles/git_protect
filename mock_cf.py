#!/usr/bin/env python3
"""Minimal in-memory Cloudflare DNS API, enough to exercise every write path.

Started by test/integration.sh. Writes its port to $PORTFILE so the harness does
not need a fixed port.
"""
import http.server, json, os, re, sys, uuid, urllib.parse

ZONE = "example.test"
ZONE_ID = "zone0000000000000000000000000001"
TOKEN = "TESTTOKENabcdefghijklmnopqrstuvwxyz012345"

records = {}


def seed():
    def add(name, rtype, content, **kw):
        rid = uuid.uuid4().hex
        records[rid] = dict(id=rid, name=name, type=rtype, content=content,
                            ttl=kw.get("ttl", 1), proxied=kw.get("proxied", False),
                            comment=kw.get("comment", ""), tags=kw.get("tags", []),
                            priority=kw.get("priority"))
        return rid
    add(ZONE, "TXT", "v=spf1 include:mailgun.org -all")
    add(f"_dmarc.{ZONE}", "TXT", "v=DMARC1; p=quarantine; rua=mailto:d@example.test")
    add(f"_dmarc.{ZONE}", "TXT", "v=DMARC1; p=quarantine; rua=mailto:d@example.test",
        comment="duplicate")
    add(f"mail.{ZONE}", "MX", "mx1.example.test", priority=10)
    add(f"www.{ZONE}", "A", "203.0.113.10", proxied=True, tags=["web"])
    add(f"old.{ZONE}", "CNAME", "gone.example.test", tags=["stale"])


seed()


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _auth(self):
        h = self.headers.get("Authorization", "")
        return h == f"Bearer {TOKEN}"

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fail(self, code, cfcode, msg):
        self._send(code, {"success": False, "errors": [{"code": cfcode, "message": msg}],
                          "messages": [], "result": None})

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n))
        except Exception:
            return None

    # --- validation mirroring the real API's fussier rules ---
    def _validate(self, r):
        if not r.get("name") or not r.get("type") or r.get("content") is None:
            return "name, type and content are required"
        if r["type"] in ("MX", "SRV") and r.get("priority") is None:
            return f"priority is required for {r['type']} records"
        if "proxied" in r and r["type"] not in ("A", "AAAA", "CNAME"):
            return f"proxied is not valid for {r['type']} records"
        ttl = r.get("ttl", 1)
        if ttl != 1 and not (60 <= ttl <= 86400):
            return "ttl must be 1 or between 60 and 86400"
        return None

    def do_GET(self):
        if not self._auth():
            return self._fail(403, 9109, "Invalid API token")
        p = urllib.parse.urlparse(self.path)
        if p.path.endswith("/user/tokens/verify"):
            return self._send(200, {"success": True, "errors": [], "messages": [],
                                    "result": {"id": "tok1", "status": "active",
                                               "expires_on": "2027-01-01T00:00:00Z"}})
        if p.path.endswith("/zones"):
            q = urllib.parse.parse_qs(p.query)
            name = (q.get("name") or [""])[0]
            res = [{"id": ZONE_ID, "name": ZONE}] if name == ZONE else []
            return self._send(200, {"success": True, "errors": [], "messages": [], "result": res})
        m = re.match(rf".*/zones/{ZONE_ID}/dns_records$", p.path)
        if m:
            return self._send(200, {"success": True, "errors": [], "messages": [],
                                    "result": list(records.values()),
                                    "result_info": {"count": len(records)}})
        return self._fail(404, 7000, "No route for that URI")

    def do_POST(self):
        if not self._auth():
            return self._fail(403, 9109, "Invalid API token")
        if not self.path.endswith(f"/zones/{ZONE_ID}/dns_records"):
            return self._fail(404, 7000, "No route for that URI")
        r = self._body()
        if r is None:
            return self._fail(400, 6003, "Invalid JSON in request body")
        err = self._validate(r)
        if err:
            return self._fail(400, 9005, err)
        for ex in records.values():
            if (ex["name"], ex["type"], ex["content"]) == (r["name"], r["type"], r["content"]):
                return self._fail(400, 81057, "Record already exists")
        rid = uuid.uuid4().hex
        rec = dict(id=rid, ttl=1, proxied=False, comment="", tags=[], priority=None)
        rec.update(r)
        rec["id"] = rid
        records[rid] = rec
        return self._send(200, {"success": True, "errors": [], "messages": [], "result": rec})

    def do_PUT(self):
        if not self._auth():
            return self._fail(403, 9109, "Invalid API token")
        m = re.match(rf".*/zones/{ZONE_ID}/dns_records/([0-9a-f]+)$", self.path)
        if not m:
            return self._fail(404, 7000, "No route for that URI")
        rid = m.group(1)
        if rid not in records:
            return self._fail(404, 81044, "Record does not exist")
        r = self._body()
        if r is None:
            return self._fail(400, 6003, "Invalid JSON in request body")
        err = self._validate(r)
        if err:
            return self._fail(400, 9005, err)
        rec = dict(id=rid, ttl=1, proxied=False, comment="", tags=[], priority=None)
        rec.update(r)
        rec["id"] = rid
        records[rid] = rec
        return self._send(200, {"success": True, "errors": [], "messages": [], "result": rec})

    def do_DELETE(self):
        if not self._auth():
            return self._fail(403, 9109, "Invalid API token")
        m = re.match(rf".*/zones/{ZONE_ID}/dns_records/([0-9a-f]+)$", self.path)
        if not m:
            return self._fail(404, 7000, "No route for that URI")
        rid = m.group(1)
        if rid not in records:
            return self._fail(404, 81044, "Record does not exist")
        del records[rid]
        return self._send(200, {"success": True, "errors": [], "messages": [],
                                "result": {"id": rid}})


srv = http.server.HTTPServer(("127.0.0.1", 0), H)
with open(os.environ["PORTFILE"], "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
