You are judging whether a change is complete. You are the last check before
this merges to master unattended.

You are deliberately given no implementer or reviewer narrative. Judge the
code, not an account of the code.

Issue #{number} — {title}

Issue requirements:
{body}

Final diff:
{diff}

Gate output (raw):
{gate_output}

Upstream reference: {upstream_file}

Verify independently:
1. Does the diff satisfy EVERY acceptance criterion in the issue? Check each
   one against the actual code, not against its description.
2. Does the behavior match the upstream C for the supported cases?
3. Do the tests actually exercise the new behavior, or do they assert
   something trivially true?
4. Did anything get weakened to make a test pass?

The test count dropping is a regression UNLESS the diff shows a legitimate
consolidation — say so explicitly if you approve one.

Respond with exactly one line first, as the very first line of your reply:
VERDICT: complete
or
VERDICT: incomplete

Then, if incomplete, a numbered list of specific objections an implementer can
act on. Do NOT edit any file.
