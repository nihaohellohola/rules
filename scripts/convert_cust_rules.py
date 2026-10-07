#!/usr/bin/env python3
"""Convert configured Clash payload rule files into Loon rule lists."""
import re
import sys
from pathlib import Path

MAPPINGS = {
    Path("clash/ai_cust.yaml"): Path("loon/ai_cust.list"),
    Path("clash/bd_ad_remove.yaml"): Path("loon/bd_ad_remove.list"),
    Path("clash/direct_cust.yaml"): Path("loon/direct_cust.list"),
    Path("clash/direct_ip_cust.yaml"): Path("loon/direct_ip_cust.list"),
    Path("clash/google_cust.yaml"): Path("loon/google_cust.list"),
    Path("clash/onedrive_web.yaml"): Path("loon/onedrive_web.list"),
    Path("clash/proxy_cust.yaml"): Path("loon/proxy_cust.list"),
    Path("clash/telegram_cust.yaml"): Path("loon/telegram_cust.list"),
}
SUPPORTED = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "URL-REGEX", "IP-CIDR", "IP-CIDR6"}
CIDR = re.compile(r"^[0-9A-Fa-f:.]+/\d{1,3}$")
URL_PREFIX = re.compile(r"^\^?https?://", re.IGNORECASE)
WRAPPERS = {
    Path("clash/bd_ad_remove.yaml"): "#!name=Blued AD Remove\n#!desc=Blued广告拦截。\n#!author=Modified by AI\n\n[Rule]\n",
}


def convert(source: Path) -> tuple[str, int]:
    lines = source.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "payload:") + 1
    except StopIteration as exc:
        raise ValueError(f"{source}: missing payload section") from exc

    output = []
    seen_rules = set()
    count = 0
    deduplicate = source.name in {"bd_ad_remove.yaml", "direct_cust.yaml", "onedrive_web.yaml"}
    for raw in lines[start:]:
        item = raw.strip()
        if not item:
            if output and output[-1] != "":
                output.append("")
            continue
        if item.startswith("#"):
            output.append(item)
            continue
        if item.startswith("- "):
            item = item[2:].strip()
        item = item.strip("'\" ")

        # Clash payloads may express an IP CIDR as a quoted bare CIDR.
        if CIDR.fullmatch(item):
            item = f"IP-CIDR,{item},no-resolve"
        else:
            fields = [field.strip().strip("'\"") for field in item.split(",")]
            if len(fields) < 2 or not fields[1]:
                raise ValueError(f"{source}: unsupported or malformed rule: {raw}")
            kind, value = fields[0], fields[1]
            # URL/path filters are Loon URL-REGEX rules, not domain rules.
            normalized_probe = value.replace(r"\/", "/")
            if kind in {"DOMAIN", "DOMAIN-REGEX"} and URL_PREFIX.match(normalized_probe):
                kind = "URL-REGEX"
            if kind not in SUPPORTED:
                raise ValueError(f"{source}: unsupported or malformed rule: {raw}")
            # Discard optional Clash policy/group suffixes (e.g. ,Google).
            item = f"{kind},{value}"

        if deduplicate and item in seen_rules:
            continue
        seen_rules.add(item)
        output.append(item)
        count += 1

    while output and output[-1] == "":
        output.pop()
    if count == 0:
        raise ValueError(f"{source}: no payload rules found")
    return "\n".join(output) + "\n", count


def main() -> None:
    selected = set(sys.argv[1:])
    unknown = selected - {source.stem for source in MAPPINGS}
    if unknown:
        raise SystemExit(f"unknown mapping name(s): {', '.join(sorted(unknown))}")
    for source, destination in MAPPINGS.items():
        if selected and source.stem not in selected:
            continue
        content, count = convert(source)
        content = WRAPPERS.get(source, "") + content
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        print(f"{source} -> {destination}: {count} rules")


if __name__ == "__main__":
    main()
