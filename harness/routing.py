"""Deterministic model routing.

A table, not a model call: cheaper, auditable, diffable, and tunable from
accumulated cycle data. A model choosing the model costs a request and cannot
be reviewed.
"""
import os

TIERS = ["haiku", "sonnet", "opus"]

# Ceiling on the model tier for every stage, including the judge as of
# 2026-08-16 (user directive, "until further notice"). Set to hold opus spend
# down after tier 0's run of high-risk, multi-round opus cycles.
#
# Capping the judge is a deliberate risk, not an oversight: every tier-0 defect
# it caught after a clean gate and a passing review (cache poisoning and a
# rebind-with-caching-off bypass in #3, silent lease loss on restart in #9) was
# found by opus. Whether a capped judge catches the same class of bug at the
# same rate is unverified — watch judge output closely while this is in effect.
#
# Override with HARNESS_MODEL_CEILING=opus to restore the judge to full
# strength (and design/implement along with it).
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

# Stages whose model never varies except by the ceiling above. Historically the
# judge was pinned to the top tier unconditionally, since it is the only thing
# standing between a plausible diff and master — see MODEL_CEILING's docstring
# for why that is currently overridden.
FIXED_STAGES = {"research": "sonnet", "review": "sonnet", "judge": "opus"}


def escalate(model):
    i = TIERS.index(model)
    return TIERS[min(i + 1, len(TIERS) - 1)]


def _capped(model):
    if TIERS.index(model) > TIERS.index(MODEL_CEILING):
        return MODEL_CEILING
    return model


def route(meta, stage, attempt=0):
    if stage in FIXED_STAGES:
        return _capped(FIXED_STAGES[stage])

    model = meta.model
    if meta.risk == "high" or any(f in meta.port_file for f in HOT_FILES):
        model = "opus"

    for _ in range(attempt):
        model = escalate(model)
    return _capped(model)
