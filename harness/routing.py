"""Deterministic model routing.

A table, not a model call: cheaper, auditable, diffable, and tunable from
accumulated cycle data. A model choosing the model costs a request and cannot
be reviewed.
"""
import os

TIERS = ["haiku", "sonnet", "opus"]

# Ceiling on the model tier for design/implement (and research/review, which
# already default within it). Set by the user 2026-08-16 to hold opus spend
# down after tier 0's run of high-risk, multi-round opus cycles.
#
# The judge is exempt: it is the last check before an unattended merge, not a
# cost lever, and every tier-0 defect the judge caught (cache poisoning, a
# rebind bypass, silent lease loss) was found by opus. Capping it would trade
# the one thing standing between a plausible diff and master for a lower bill.
#
# Override with HARNESS_MODEL_CEILING=opus to restore the original policy.
MODEL_CEILING = os.environ.get("HARNESS_MODEL_CEILING", "sonnet")

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


def _capped(model):
    if TIERS.index(model) > TIERS.index(MODEL_CEILING):
        return MODEL_CEILING
    return model


def route(meta, stage, attempt=0):
    if stage == "judge":
        return FIXED_STAGES["judge"]  # exempt from the ceiling; see module docstring

    if stage in FIXED_STAGES:
        return _capped(FIXED_STAGES[stage])

    model = meta.model
    if meta.risk == "high" or any(f in meta.port_file for f in HOT_FILES):
        model = "opus"

    for _ in range(attempt):
        model = escalate(model)
    return _capped(model)
