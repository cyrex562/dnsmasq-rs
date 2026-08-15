You are reviewing a diff against upstream dnsmasq for semantic drift.

Issue #{number} — {title}

{body}

Upstream reference: {upstream_file}

Diff under review:
{diff}

Check specifically:
- Does this preserve upstream's observable behavior, or does it quietly
  simplify an edge case?
- Are flag semantics and wire format preserved exactly?
- Is any config directive accepted as a silent no-op?
- Are feature gates correct and complete, including in BOTH `lib.rs` and
  `main.rs`?
- Are capability-dependent tests gated so restricted environments do not fail?
- Does every behavior change have a test, and does that test actually exercise
  the new behavior rather than assert something trivially true?
- If this wires up previously-unused code, is it wired at the right place in
  the control flow, matching upstream's ordering?

Report only issues that matter, most severe first. If the diff is sound, say so
plainly. Do NOT edit any file.
