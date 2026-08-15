You are designing the implementation for a dnsmasq port issue before any code
is written.

Issue #{number} — {title}

{body}

Research findings:
{research}

Produce a short implementation approach:
- The order of changes, smallest coherent step first.
- Which existing types and functions to reuse rather than reinvent. This port
  frequently already contains the logic needed, unwired — prefer connecting
  what exists over writing a parallel implementation.
- Where the risk of semantic drift from upstream is highest, and how to avoid it.
- The test strategy: what is unit-testable, what needs an integration test, and
  what can only be verified by the parity fixture.

Be specific and short. Do NOT edit any file.
