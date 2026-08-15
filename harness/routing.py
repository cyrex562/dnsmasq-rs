"""Deterministic model routing.

A table, not a model call: cheaper, auditable, diffable, and tunable from
accumulated cycle data. A model choosing the model costs a request and cannot
be reviewed.
"""

TIERS = ["haiku", "sonnet", "opus"]

# Files where a wrong edit is expensive or the logic is intricate enough that
# the cheapest capable model is not the cheapest outcome.
HOT_FILES = (
    "src/option.rs",
    "src/forward.rs",
    "src/dnssec.rs",
    "src/network.rs",
    "src/rfc1035.rs",
    "src/crypto.rs",
)

# Stages whose model never varies. The judge is pinned to the top tier because
# it is the only thing standing between a plausible diff and master.
FIXED_STAGES = {"research": "sonnet", "review": "sonnet", "judge": "opus"}


def escalate(model):
    i = TIERS.index(model)
    return TIERS[min(i + 1, len(TIERS) - 1)]


def route(meta, stage, attempt=0):
    if stage in FIXED_STAGES:
        return FIXED_STAGES[stage]

    model = meta.model
    if meta.risk == "high" or any(f in meta.port_file for f in HOT_FILES):
        model = "opus"

    for _ in range(attempt):
        model = escalate(model)
    return model
