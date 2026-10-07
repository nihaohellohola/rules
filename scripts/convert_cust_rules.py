#!/usr/bin/env python3
"""Convert repository clash/*cust*.yaml payloads into Loon rule lists."""
import re
from pathlib import Path

MAPPINGS = {
    Path("clash/ai_cust.yaml"): Path("loon/ai_cust.list"),
    Path("clash/direct_cust.yaml"): Path("loon/direct_cust.list"),
    Path("clash/direct_ip_cust.yaml"): Path("loon/direct_ip_cust.list"),
    Path("clash/google_cust.yaml"): Path("loon/google_cust.list"),
    Path("clash/proxy_cust.yaml"): Path("loon/proxy_cust.list"),
    Path("clash/telegram_cust.yaml"): Path("loon/telegram_cust.list"),
}
SUPPORTED = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "IP-CIDR", "IP-CIDR6"}
CIDR = re.compile(r"^[0-9A-Fa-f:.]+/\d{1,3}$")


def convert(source: Path) -> str:
    lines = source.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "payload:") + 1
    except StopIteration as exc:
        raise ValueError(f"{source}: missing payload section") from exc

    output = []
    count = 0
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
            kind = fields[0]
            if kind not in SUPPORTED or len(fields) < 2 or not fields[1]:
                raise ValueError(f"{source}: unsupported or malformed rule: {raw}")
            # Discard optional Clash policy/group suffixes (e.g. ,Google).
            item = ",".join(fields[:2])
        output.append(item)
        count += 1

    while output and output[-1] == "":
        output.pop()
    if count == 0:
        raise ValueError(f"{source}: no payload rules found")
    return "\n".join(output) + "\n"


def main() -> None:
    for source, destination in MAPPINGS.items():
        content = convert(source)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        print(f"{source} -> {destination}: {sum(1 for line in content.splitlines() if line and not line.startswith('#'))} rules")


if __name__ == "__main__":
    main()
