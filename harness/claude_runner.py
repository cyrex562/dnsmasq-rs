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
    cmd = [
        "claude", "-p", prompt,
        "--model", model,
        "--output-format", "json",
        "--add-dir", cwd,
    ]
    if read_only:
        cmd += ["--allowedTools", READ_ONLY_TOOLS]
    else:
        cmd += ["--permission-mode", "bypassPermissions"]

    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
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
