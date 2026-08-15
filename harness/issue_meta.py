"""Parse the fenced `harness` metadata block out of a GitHub issue body."""
import json
import re
import subprocess
from dataclasses import dataclass, field

BLOCK_RE = re.compile(r"```harness\s*\n(.*?)```", re.DOTALL)
REPO = "cyrex562/dnsmasq-rs"

REQUIRED = ("key", "tier", "risk", "model-tier", "port-file", "upstream-file")


@dataclass
class IssueMeta:
    number: int
    key: str
    tier: int
    risk: str
    model: str
    port_file: str
    upstream_file: str
    gate_profile: str
    blocked_by: list = field(default_factory=list)
    title: str = ""
    body: str = ""

    @property
    def wants_parity(self):
        return self.gate_profile == "full+parity"


def parse_meta(number, title, body):
    m = BLOCK_RE.search(body or "")
    if not m:
        return None

    fields = {}
    for line in m.group(1).splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        fields[k.strip()] = v.strip()

    if any(r not in fields for r in REQUIRED):
        return None

    blocked = fields.get("blocked-by", "none")
    blocked_list = [] if blocked in ("none", "") else [b.strip() for b in blocked.split(",")]

    try:
        tier = int(fields["tier"])
    except ValueError:
        return None

    return IssueMeta(
        number=number,
        key=fields["key"],
        tier=tier,
        risk=fields["risk"],
        model=fields["model-tier"],
        port_file=fields["port-file"],
        upstream_file=fields["upstream-file"],
        gate_profile=fields.get("gate-profile", "full"),
        blocked_by=blocked_list,
        title=title,
        body=body,
    )


def select_next(issues, closed_keys):
    """Lowest tier first, then lowest issue number, skipping blocked issues."""
    eligible = [i for i in issues if all(b in closed_keys for b in i.blocked_by)]
    if not eligible:
        return None
    return sorted(eligible, key=lambda i: (i.tier, i.number))[0]


def fetch_open_issues(repo=REPO, label="port"):
    out = subprocess.run(
        ["gh", "issue", "list", "--repo", repo, "--label", label, "--state", "open",
         "--limit", "200", "--json", "number,title,body,labels"],
        capture_output=True, text=True, check=True,
    ).stdout
    metas = []
    for row in json.loads(out):
        names = {lbl["name"] for lbl in row.get("labels", [])}
        if "parked" in names or "needs-human" in names:
            continue
        m = parse_meta(row["number"], row["title"], row["body"])
        if m:
            metas.append(m)
    return metas


def fetch_closed_keys(repo=REPO, label="port"):
    out = subprocess.run(
        ["gh", "issue", "list", "--repo", repo, "--label", label, "--state", "closed",
         "--limit", "200", "--json", "number,title,body"],
        capture_output=True, text=True, check=True,
    ).stdout
    keys = set()
    for row in json.loads(out):
        m = parse_meta(row["number"], row["title"], row["body"])
        if m:
            keys.add(m.key)
    return keys
