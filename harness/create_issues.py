#!/usr/bin/env python3
"""Render and file the port issue corpus.

  ./harness/create_issues.py --dry-run     # print what would be filed
  ./harness/create_issues.py               # file them via gh
"""
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from issues import ISSUES  # noqa: E402

REPO = "cyrex562/dnsmasq-rs"
TIER_LABEL = {
    0: "tier:0-integration",
    1: "tier:1-correctness",
    2: "tier:2-config",
    3: "tier:3-depth",
}
TIER_NAME = {
    0: "Tier 0 — Integration (blocking)",
    1: "Tier 1 — Correctness / security",
    2: "Tier 2 — Config parity",
    3: "Tier 3 — Per-file depth",
}
# Files whose behavior the DNS parity fixture can observe.
PARITY_HINTS = ("rfc1035", "forward", "cache", "domain", "edns0", "rrfilter",
                "dnsmasq.rs", "main.rs", "network.rs", "auth", "dnssec", "option.rs")


def gate_profile(issue):
    return "full+parity" if any(h in issue["port_file"] for h in PARITY_HINTS) else "full"


def render(issue):
    parts = []
    parts.append(f"**{TIER_NAME[issue['tier']]}**\n")
    parts.append(issue["summary"])
    parts.append("\n## Gaps\n")
    parts.extend(f"- [ ] {g}" for g in issue["gaps"])
    parts.append("\n## Acceptance criteria\n")
    parts.extend(f"- [ ] {a}" for a in issue["acceptance"])

    if issue["blocked_by"]:
        parts.append("\n## Blocked by\n")
        parts.append(", ".join(f"`{k}`" for k in issue["blocked_by"]))

    parts.append(
        "\n## Porting rules\n\n"
        "Read the upstream C for this behavior before writing Rust. Preserve observable "
        "upstream behavior, including flag semantics and wire format. Do not accept a config "
        "directive as a silent no-op. Keep anything left unsupported explicit in `tasks.md`.\n\n"
        "**Note:** `src/lib.rs` and `src/main.rs` each declare the full module tree separately. "
        "Adding a module requires editing both, with matching `#[cfg(feature = ...)]` gates, or "
        "the binary silently loses it."
    )

    parts.append("\n## Harness metadata\n")
    parts.append("```harness")
    parts.append(f"key: {issue['key']}")
    parts.append(f"tier: {issue['tier']}")
    parts.append(f"risk: {issue['risk']}")
    parts.append(f"model-tier: {issue['model']}")
    parts.append(f"port-file: {issue['port_file']}")
    parts.append(f"upstream-file: {issue['upstream_file']}")
    parts.append(f"gate-profile: {gate_profile(issue)}")
    parts.append(f"blocked-by: {','.join(issue['blocked_by']) if issue['blocked_by'] else 'none'}")
    parts.append("```")
    parts.append(
        "\n<sub>Generated from a five-agent gap audit of all 50 upstream files, 2026-08-14. "
        "See `docs/superpowers/specs/2026-08-14-port-harness-design.md`.</sub>"
    )
    return "\n".join(parts)


def labels_for(issue):
    ls = ["port", TIER_LABEL[issue["tier"]], f"risk:{issue['risk']}", f"model:{issue['model']}"]
    ls.extend(issue.get("extra_labels", []))
    return ls


def main():
    dry = "--dry-run" in sys.argv
    by_tier = {}
    for i in ISSUES:
        by_tier.setdefault(i["tier"], []).append(i)

    keys = [i["key"] for i in ISSUES]
    assert len(keys) == len(set(keys)), "duplicate keys"
    for i in ISSUES:
        for b in i["blocked_by"]:
            assert b in keys, f"{i['key']} blocked by unknown key {b}"

    print(f"{len(ISSUES)} issues total")
    for t in sorted(by_tier):
        print(f"  tier {t}: {len(by_tier[t])}")
    print()

    if dry:
        for t in sorted(by_tier):
            print(f"── {TIER_NAME[t]} ──")
            for i in by_tier[t]:
                print(f"  [{i['key']:<16}] {i['title']}")
                print(f"  {' ' * 18}{','.join(labels_for(i))}  gate={gate_profile(i)}")
        print("\n(dry run — nothing filed)")
        return

    created = []
    for i in ISSUES:
        cmd = ["gh", "issue", "create", "--repo", REPO,
               "--title", i["title"], "--body", render(i)]
        for lab in labels_for(i):
            cmd += ["--label", lab]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL {i['key']}: {r.stderr.strip()}", file=sys.stderr)
            sys.exit(1)
        url = r.stdout.strip()
        created.append((i["key"], url))
        print(f"{i['key']:<16} {url}", flush=True)

    print(f"\ncreated {len(created)} issues")


if __name__ == "__main__":
    main()
