"""Per-cycle records, written under harness/state/."""
import json
import os
import re
from dataclasses import asdict, dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(HERE, "state")


@dataclass
class CycleRecord:
    key: str
    number: int
    title: str
    stages: list = field(default_factory=list)
    gate_failures: list = field(default_factory=list)
    verdict: str = ""
    objections: str = ""
    pr_url: str = ""
    parked_branch: str = ""
    merged: bool = False
    reverted: bool = False
    outcome: str = "started"


def save_record(record, state_dir=STATE_DIR):
    os.makedirs(state_dir, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]", "-", record.key).lower()
    path = os.path.join(state_dir, f"{record.number:04d}-{safe}.json")
    with open(path, "w") as f:
        json.dump(asdict(record), f, indent=2)
        f.write("\n")
    return path
