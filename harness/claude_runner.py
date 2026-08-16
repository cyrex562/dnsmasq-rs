"""Render stage templates and execute them through headless `claude -p`."""
import json
import os
import re
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
STAGES = os.path.join(HERE, "stages")

# Tools a read-only stage may use. Research, review, and judge must not be able
# to edit the tree — the judge especially, or it can quietly fix what it is
# supposed to be grading and then approve its own repair.
READ_ONLY_TOOLS = (
    "Read,Grep,Glob,"
    "Bash(cargo test:*),Bash(cargo check:*),"
    "Bash(git diff:*),Bash(git log:*),Bash(git show:*)"
)

# Tools the implement stage may use. This is deliberately an allowlist rather
# than `--permission-mode bypassPermissions`: the stage runs unattended on a
# developer machine, and it only ever needs to edit the tree and drive cargo
# and git. Bypassing permissions would additionally grant arbitrary shell —
# network access, package installs, writes outside the worktree — none of
# which any port issue requires.
WRITE_TOOLS = (
    "Read,Grep,Glob,Write,Edit,NotebookEdit,TodoWrite,"
    "Bash(cargo:*),Bash(git:*),"
    "Bash(ls:*),Bash(cat:*),Bash(head:*),Bash(tail:*),Bash(wc:*),Bash(rg:*),"
    "Bash(mkdir:*),Bash(cp:*),Bash(mv:*),Bash(diff:*),Bash(sed:*),Bash(awk:*)"
)

# Escape hatch for running in a throwaway sandbox (container, VM) where the
# allowlist gets in the way more than it protects. Off by default, on purpose.
BYPASS_ENV = "HARNESS_BYPASS_PERMISSIONS"

VERDICT_RE = re.compile(r"^\s*VERDICT:\s*(complete|incomplete)\s*$", re.I | re.M)

# The judge template requires its verdict on the first line. Allowing a little
# slack tolerates a stray blank line or preamble without accepting a verdict
# buried under paragraphs of hedging.
VERDICT_SEARCH_LINES = 20


class StageError(RuntimeError):
    pass


def render(stage, **kw):
    with open(os.path.join(STAGES, f"{stage}.md")) as f:
        out = f.read()
    for key, value in kw.items():
        out = out.replace("{" + key + "}", str(value))
    return out


def run_stage(stage, model, cwd, prompt, read_only=False, timeout=5400):
    # The prompt goes in on stdin, never as an argv element. Linux caps a
    # single argument at MAX_ARG_STRLEN (131072 bytes), and judge prompts embed
    # the full diff: a 136969-byte diff killed a cycle at the judge stage with
    # "Argument list too long" after the work was already done and gate-clean.
    # ARG_MAX (2MB) is not the binding limit here — the per-argument one is.
    cmd = [
        "claude", "-p",
        "--model", model,
        "--output-format", "json",
        "--add-dir", cwd,
    ]
    if read_only:
        cmd += ["--allowedTools", READ_ONLY_TOOLS]
    elif os.environ.get(BYPASS_ENV) == "1":
        cmd += ["--permission-mode", "bypassPermissions"]
    else:
        cmd += ["--allowedTools", WRITE_TOOLS, "--permission-mode", "acceptEdits"]

    proc = subprocess.run(cmd, input=prompt, cwd=cwd,
                          capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise StageError(f"{stage} exited {proc.returncode}: {proc.stderr[-1000:]}")

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return proc.stdout.strip()

    if isinstance(payload, dict):
        return payload.get("result") or payload.get("text") or proc.stdout.strip()
    return proc.stdout.strip()


def parse_verdict(text):
    """Extract the judge's verdict. Fails closed.

    A VERDICT buried under paragraphs of hedging is treated as no verdict. It
    usually means the model reasoned its way toward a conclusion instead of
    committing to one, and defaulting that to 'complete' would be the single
    most dangerous failure mode in this harness — it is the last check before
    an unattended merge to master.
    """
    head = "\n".join((text or "").splitlines()[:VERDICT_SEARCH_LINES])
    m = VERDICT_RE.search(head)
    if not m:
        return False, (
            f"judge produced no VERDICT line in the first {VERDICT_SEARCH_LINES} "
            "lines; treating as incomplete"
        )
    if m.group(1).lower() == "complete":
        return True, ""
    return False, text[m.end():].strip()
