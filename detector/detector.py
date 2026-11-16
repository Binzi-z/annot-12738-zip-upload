"""Correlating detector for the zip-upload -> auto-extract -> executable-access chain.

Replaces the baseline (one alert per failed login / per request) with three
correlated rules plus a needs_review queue for partial chains:

  archive_webshell        upload endpoint/archive request, then a request for an
                          executable file under the extraction directory from the
                          same IP within CHAIN_WINDOW seconds.
  web_scan                one IP probing >= SCAN_MIN_PATHS distinct sensitive
                          paths (a couple of denied probes is benign noise).
  privilege_escalation    non-root user sudo-ing to a root shell, followed by an
                          SSH root login within PRIVESC_WINDOW seconds.

Every finding carries rule/first_seen/last_seen/entities/evidence; the webshell
chain also carries a timeline (upload -> extract -> access). Partial chains go
to needs_review with an explicit note about which link is missing.
"""

from __future__ import annotations

import json
import re
import sys
from collections import defaultdict

TS = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})")
NGINX = re.compile(r'nginx:\s+(?P<ip>[\d.]+)\s+-\s+-\s+"(?P<path>\S+)"\s+(?P<status>\d{3})')
SSH_OK = re.compile(r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)")
SUDO = re.compile(r"sudo:\s+(?P<user>\S+)\s+:.*?USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.+?)\s*$")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

# Sensitive paths worth counting toward a scan. Exact matches plus prefixes.
SENSITIVE_EXACT = {
    "/admin", "/.env", "/wp-login.php", "/wp-admin", "/phpmyadmin",
    "/backup.zip", "/backup.tar.gz", "/.git/config", "/config.php",
    "/.htaccess", "/server-status", "/xmlrpc.php",
}
SENSITIVE_PREFIX = ("/.git", "/.env", "/wp-", "/phpmyadmin", "/backup")

# Extensions we treat as executable once extracted into the site directory.
EXEC_EXT = (".php", ".phtml", ".jsp", ".jspx", ".asp", ".aspx",
            ".exe", ".sh", ".pl", ".py", ".cgi", ".war")
ARCHIVE_EXT = (".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z")
SHELL_BINS = {"sh", "bash", "zsh", "dash", "ksh", "su"}

SCAN_MIN_PATHS = 4      # benign look-alike in corpus probes only 2
CHAIN_WINDOW = 3600     # upload -> executable access
PRIVESC_WINDOW = 600    # sudo root shell -> root ssh login


def parse(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8") as fh:
        for no, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            ts = TS.match(line)
            if not ts:
                continue
            h, m, s = map(int, ts.group("hms").split(":"))
            secs = (MONTHS[ts.group("mon")] * 31 + int(ts.group("day"))) * 86400 \
                + h * 3600 + m * 60 + s
            base = {"line": no, "ts": ts.group(0), "secs": secs, "raw": line.strip()}

            m_ = NGINX.search(line)
            if m_:
                full = m_.group("path")
                p, _, query = full.partition("?")
                events.append({**base, "kind": "web", "ip": m_.group("ip"),
                               "path": p, "query": query,
                               "status": int(m_.group("status"))})
                continue
            m_ = SSH_OK.search(line)
            if m_:
                events.append({**base, "kind": "ssh_ok",
                               "user": m_.group("user"), "ip": m_.group("ip")})
                continue
            m_ = SUDO.search(line)
            if m_:
                events.append({**base, "kind": "sudo", "user": m_.group("user"),
                               "target": m_.group("target"),
                               "cmd": m_.group("cmd").strip()})
    return events


def is_sensitive(path: str) -> bool:
    p = path.lower()
    return p in SENSITIVE_EXACT or p.startswith(SENSITIVE_PREFIX)


def is_upload(ev: dict) -> bool:
    p = ev["path"].lower()
    seg = p.rsplit("/", 1)[-1]  # endpoint name, not the extraction directory
    return 200 <= ev["status"] < 300 and (
        "upload" in seg or p.endswith(ARCHIVE_EXT))


def is_executable(path: str) -> bool:
    return path.lower().endswith(EXEC_EXT)


def extract_dir(path: str) -> str:
    """Directory the archive was extracted into, derived from the accessed file."""
    if "/" in path.lstrip("/"):
        return "/" + path.lstrip("/").split("/", 1)[0] + "/"
    return "/"


def ev_ref(ev: dict) -> dict:
    return {"line": ev["line"], "ts": ev["ts"], "raw": ev["raw"]}


def finding(rule: str, evs: list[dict], entities: dict,
            evidence: list[dict], severity: str = "high",
            timeline: list[dict] | None = None) -> dict:
    f = {
        "rule": rule,
        "severity": severity,
        "first_seen": min(e["ts"] for e in evs),
        "last_seen": max(e["ts"] for e in evs),
        "entities": entities,
        "evidence": evidence,
        "line": min(e["line"] for e in evs),
    }
    if "ip" in entities:
        f["ip"] = entities["ip"]
    if timeline:
        f["timeline"] = timeline
    return f


def detect_web_scan(webs: list[dict]) -> list[dict]:
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in webs:
        if is_sensitive(ev["path"]):
            by_ip[ev["ip"]].append(ev)
    out = []
    for ip, hits in by_ip.items():
        paths = sorted({h["path"] for h in hits})
        if len(paths) < SCAN_MIN_PATHS:
            continue  # a couple of denied probes is background noise
        out.append(finding(
            "web_scan", hits,
            {"ip": ip, "paths": paths},
            [ev_ref(h) for h in hits],
            severity="medium"))
    return out


def detect_archive_webshell(webs: list[dict]) -> tuple[list[dict], list[dict]]:
    findings, review = [], []
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for ev in webs:
        by_ip[ev["ip"]].append(ev)

    for ip, evs in by_ip.items():
        uploads = [e for e in evs if is_upload(e)]
        execs = [e for e in evs
                 if is_executable(e["path"]) and not is_upload(e)
                 and 200 <= e["status"] < 300]
        chains, used_up, used_ex = [], set(), set()
        for ex in execs:
            prior = [u for u in uploads if 0 <= ex["secs"] - u["secs"] <= CHAIN_WINDOW]
            if prior:
                up = min(prior, key=lambda u: u["secs"])
                chains.append((up, ex))
                used_up.add(up["line"])
                used_ex.add(ex["line"])

        if chains:
            ups = sorted({u["line"]: u for u, _ in chains}.values(),
                         key=lambda u: u["secs"])
            exs = sorted({e["line"]: e for _, e in chains}.values(),
                         key=lambda e: e["secs"])
            timeline = [
                {"ts": u["ts"], "stage": "upload", "archive": u["path"],
                 "line": u["line"]} for u in ups]
            timeline += [
                {"ts": exs[0]["ts"], "stage": "extract",
                 "path": extract_dir(e["path"]),
                 "note": "auto-extract directory inferred from accessed file",
                 "inferred": True}
                for e in exs[:1]]
            timeline += [
                {"ts": e["ts"], "stage": "access", "file": e["path"],
                 "query": e["query"] or None, "line": e["line"]} for e in exs]
            order = {"upload": 0, "extract": 1, "access": 2}
            timeline.sort(key=lambda t: (t["ts"], order[t["stage"]]))
            evs_all = ups + exs
            findings.append(finding(
                "archive_webshell", evs_all,
                {"ip": ip,
                 "archives": [u["path"] for u in ups],
                 "extract_dirs": sorted({extract_dir(e["path"]) for e in exs}),
                 "executed_files": [e["path"] for e in exs]},
                [ev_ref(e) for e in evs_all],
                timeline=timeline))

        # Partial chains -> needs_review, never an alert.
        for u in uploads:
            if u["line"] not in used_up:
                review.append({
                    "rule": "archive_webshell", "status": "needs_review",
                    "missing": ["未见上传后对该压缩包内可执行文件的访问记录"],
                    "entities": {"ip": ip, "archive": u["path"]},
                    "evidence": [ev_ref(u)]})
        for e in execs:
            if e["line"] not in used_ex:
                review.append({
                    "rule": "archive_webshell", "status": "needs_review",
                    "missing": ["缺少同一来源 IP 的上传/解压记录，"
                                "无法确认文件来自压缩包通道（可能日志窗口外上传）"],
                    "entities": {"ip": ip, "executed_file": e["path"]},
                    "evidence": [ev_ref(e)]})
    return findings, review


def detect_privilege_escalation(events: list[dict]) -> tuple[list[dict], list[dict]]:
    findings, review = [], []
    sudos = [e for e in events if e["kind"] == "sudo"
             and e["target"] == "root" and e["user"] != "root"
             and e["cmd"].split()[0].rsplit("/", 1)[-1] in SHELL_BINS]
    root_logins = [e for e in events if e["kind"] == "ssh_ok" and e["user"] == "root"]
    for su in sudos:
        follow = [r for r in root_logins
                  if 0 <= r["secs"] - su["secs"] <= PRIVESC_WINDOW]
        if follow:
            login = min(follow, key=lambda r: r["secs"])
            findings.append(finding(
                "privilege_escalation", [su, login],
                {"user": su["user"], "target_user": "root", "ip": login["ip"]},
                [ev_ref(su), ev_ref(login)]))
        else:
            review.append({
                "rule": "privilege_escalation", "status": "needs_review",
                "missing": ["sudo 起 root shell 后未见窗口内的 root 登录，"
                            "无法确认提权被实际利用"],
                "entities": {"user": su["user"], "target_user": "root"},
                "evidence": [ev_ref(su)]})
    return findings, review


def scan(path: str) -> dict:
    events = parse(path)
    webs = [e for e in events if e["kind"] == "web"]
    findings = detect_web_scan(webs)
    shell_f, shell_r = detect_archive_webshell(webs)
    priv_f, priv_r = detect_privilege_escalation(events)
    findings += shell_f + priv_f
    findings.sort(key=lambda f: f["line"])
    return {"findings": findings, "needs_review": shell_r + priv_r}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: detector.py <log> <out.json>")
        return 2
    result = scan(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(f"{len(result['findings'])} findings, "
          f"{len(result['needs_review'])} needs_review -> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
