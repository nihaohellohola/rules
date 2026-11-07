#!/usr/bin/env python3
"""Convert configured Clash payload rule files into Egern YAML rule sets."""
import ipaddress
import re
import sys
from pathlib import Path

SOURCES = [
    Path("clash/ai_cust.yaml"), Path("clash/bd_ad_remove.yaml"),
    Path("clash/direct_cust.yaml"), Path("clash/direct_ip_cust.yaml"),
    Path("clash/google_cust.yaml"), Path("clash/onedrive_web.yaml"),
    Path("clash/proxy_cust.yaml"), Path("clash/reject_cust.yaml"),
    Path("clash/telegram_cust.yaml"),
]
KEYS = {"DOMAIN": "domain_set", "DOMAIN-SUFFIX": "domain_suffix_set",
        "DOMAIN-KEYWORD": "domain_keyword_set", "DOMAIN-REGEX": "domain_regex_set",
        "IP-CIDR": "ip_cidr_set", "IP-CIDR6": "ip_cidr_set"}


def convert(source: Path) -> tuple[str, int]:
    lines = source.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "payload:") + 1
    except StopIteration as exc:
        raise ValueError(f"{source}: missing payload section") from exc
    groups: dict[str, list[tuple[str, str | None]]] = {}
    for raw in lines[start:]:
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        if item.startswith("-"):
            item = item[1:].strip()
        item = item.strip("'\" ")
        fields = [f.strip().strip("'\"") for f in item.split(",")]
        if len(fields) == 1:
            try:
                ipaddress.ip_network(fields[0], strict=False)
                kind, value = "IP-CIDR", fields[0]
                options = []
            except ValueError as exc:
                raise ValueError(f"{source}: unsupported rule: {raw}") from exc
        else:
            kind, value = fields[0].upper(), fields[1]
            options = fields[2:]
        if kind not in KEYS or not value:
            raise ValueError(f"{source}: unsupported or malformed rule: {raw}")
        suffix = ""
        if kind in {"IP-CIDR", "IP-CIDR6"}:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"{source}: invalid IP network: {raw}") from exc
            if "no-resolve" in [x.lower() for x in options]:
                suffix = ", no_resolve: true"
        elif options:
            # Clash policy suffixes (e.g. Google) are routing metadata, not match data.
            if any(option.lower() == "no-resolve" for option in options):
                raise ValueError(f"{source}: no-resolve is only valid for IP rules: {raw}")
        groups.setdefault(KEYS[kind], []).append((value, suffix))
    if not groups:
        raise ValueError(f"{source}: no supported rules found")
    out = []
    for key in ("domain_set", "domain_suffix_set", "domain_keyword_set", "domain_regex_set", "ip_cidr_set"):
        if key not in groups:
            continue
        out.append(f"{key}:")
        out.extend(f"  - {value}{suffix}" for value, suffix in groups[key])
    return "\n".join(out) + "\n", sum(map(len, groups.values()))


def main() -> None:
    selected = set(sys.argv[1:])
    known = {p.stem for p in SOURCES}
    if selected - known:
        raise SystemExit(f"unknown mapping name(s): {', '.join(sorted(selected - known))}")
    for source in SOURCES:
        if selected and source.stem not in selected:
            continue
        if not source.exists():
            if source.stem == "reject_cust":
                continue
            raise SystemExit(f"required source file missing: {source}")
        content, count = convert(source)
        destination = Path("egern") / f"{source.stem}.yaml"
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        print(f"{source} -> {destination}: {count} rules")


if __name__ == "__main__":
    main()
