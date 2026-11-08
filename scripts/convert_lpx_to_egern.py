#!/usr/bin/env python3
"""Convert configured upstream Loon .lpx plugins into Egern YAML modules."""
from __future__ import annotations
import json
import re
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts" / "egern_lpx_sources.json"


def quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def parse(text: str) -> str:
    meta = {}
    for line in text.splitlines():
        match = re.match(r"^\\s*#!([\\w-]+)\\s*=\\s*(.*?)\\s*$", line)
        if match:
            meta[match.group(1).lower()] = match.group(2)
    hostnames, scriptings = [], []
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^\\[([^]]+)\\]", line)
        if m:
            section = m.group(1).strip().lower()
            continue
        if not line or line.startswith(("#", ";")):
            continue
        if section == "mitm":
            hm = re.match(r"hostname\\s*=\\s*(.*)", line, re.I)
            if hm:
                hostnames.extend(x.strip() for x in hm.group(1).split(",") if x.strip())
        elif section == "script":
            sm = re.match(r"(response|request)\\s+if\\s+(.+?)\\s+then\\s+script\\((['\\\"])(.*?)\\3\\)(.*)", line, re.I)
            if not sm:
                raise ValueError(f"Unsupported [Script] row: {line}")
            kind, condition, _, url, options = sm.groups()
            match = condition.strip()
            if match.startswith("${url} ~= "):
                match = match[len("${url} ~= "):].strip()
            tag = re.search(r"\\btag\\s*=\\s*(['\\\"])(.*?)\\1", options)
            requires = re.search(r"\\brequires_body\\s*=\\s*(true|false)", options, re.I)
            entry = {"type": "http_response" if kind.lower() == "response" else "http_request", "match": match, "script_url": url}
            if tag:
                entry["name"] = tag.group(2)
            if requires:
                entry["body_required"] = requires.group(1).lower() == "true"
            scriptings.append(entry)
    if not scriptings:
        raise ValueError("No supported script rows found")
    out = []
    for key in ("name", "desc", "author", "icon"):
        if meta.get(key):
            out.append({"name": "name", "desc": "description"}.get(key, key) + ": " + quote(meta[key]))
    if hostnames:
        out.append("mitm:")
        out.append("  hostnames:")
        out.extend("    - " + quote(host) for host in dict.fromkeys(hostnames))
    out.append("scriptings:")
    for entry in scriptings:
        out.append("  - " + entry["type"] + ":")
        if "name" in entry:
            out.append("      name: " + quote(entry["name"]))
        out.append("      match: " + quote(entry["match"]))
        out.append("      script_url: " + quote(entry["script_url"]))
        if "body_required" in entry:
            out.append("      body_required: " + ("true" if entry["body_required"] else "false"))
    return "\\n".join(out) + "\\n"


def main() -> None:
    sources = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for item in sources:
        url, output = item["url"], ROOT / item["output"]
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            text = response.read().decode("utf-8-sig")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(parse(text), encoding="utf-8")
        print(f"Converted {url} -> {output.relative_to(ROOT)}")

if __name__ == "__main__":
    main()
