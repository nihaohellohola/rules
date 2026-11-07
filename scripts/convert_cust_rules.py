#!/usr/bin/env python3
"""Convert configured Clash payload rule files into Egern rule-set YAML."""
import ipaddress
from pathlib import Path

SOURCES = [
    "ai_cust", "bd_ad_remove", "direct_cust", "direct_ip_cust", "google_cust",
    "onedrive_web", "proxy_cust", "reject_cust", "telegram_cust",
]
KEYS = {"DOMAIN": "domain_set", "DOMAIN-SUFFIX": "domain_suffix_set",
        "DOMAIN-KEYWORD": "domain_keyword_set", "DOMAIN-REGEX": "domain_regex_set",
        "IP-CIDR": "ip_cidr_set", "IP-CIDR6": "ip_cidr6_set"}
ORDER = ["domain_set", "domain_suffix_set", "domain_keyword_set", "domain_regex_set", "ip_cidr_set", "ip_cidr6_set"]


def convert(source: Path) -> tuple[str, int]:
    lines = source.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "payload:") + 1
    except StopIteration as exc:
        raise ValueError(f"{source}: missing payload section") from exc
    groups: dict[str, list[str]] = {}
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
                kind, value, options = "IP-CIDR6" if ":" in fields[0] else "IP-CIDR", fields[0], []
            except ValueError as exc:
                raise ValueError(f"{source}: malformed/unsupported rule: {raw}") from exc
        else:
            kind, value, options = fields[0].upper(), fields[1], fields[2:]
        if kind not in KEYS or not value:
            raise ValueError(f"{source}: malformed/unsupported rule: {raw}")
        key = KEYS[kind]
        if key in {"ip_cidr_set", "ip_cidr6_set"}:
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"{source}: invalid IP network: {raw}") from exc
            if (kind == "IP-CIDR" and net.version != 4) or (kind == "IP-CIDR6" and net.version != 6):
                raise ValueError(f"{source}: IP family mismatch: {raw}")
            if "no-resolve" in [x.lower() for x in options]:
                groups.setdefault("__no_resolve__", []).append("true")
            elif any(x.lower() == "no-resolve" for x in options):
                raise ValueError(f"{source}: invalid no-resolve option: {raw}")
        elif options and any(x.lower() == "no-resolve" for x in options):
            raise ValueError(f"{source}: no-resolve is only valid for IP rules: {raw}")
        # Other trailing Clash fields are policy/routing metadata and are not match values.
        groups.setdefault(key, []).append(value)
    if not any(k in groups for k in ORDER):
        raise ValueError(f"{source}: no supported rules found")
    out = []
    if "__no_resolve__" in groups:
        out.append("no_resolve: true")
    for key in ORDER:
        if key in groups:
            out.append(f"{key}:")
            out.extend(f"  - {value}" for value in groups[key])
    return "\n".join(out) + "\n", sum(len(groups.get(k, [])) for k in ORDER)


def main() -> None:
    root = Path("clash")
    out = Path("egern")
    out.mkdir(parents=True, exist_ok=True)
    for stem in SOURCES:
        src = root / f"{stem}.yaml"
        if not src.exists():
            if stem == "reject_cust":
                continue
            raise SystemExit(f"required source file missing: {src}")
        text, count = convert(src)
        (out / f"{stem}.yaml").write_text(text, encoding="utf-8")
        print(f"{src} -> {out / (stem + '.yaml')}: {count} rules")


if __name__ == "__main__":
    main()
