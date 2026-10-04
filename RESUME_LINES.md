# Resume lines (numbers from VERIFY.md only)

- Exposed a Razorpay payment-policy proxy as an MCP server (official Python SDK, stdio + streamable-HTTP); live Groq gpt-oss-120b agent attempted 4 injected attacker refunds, 0 executed.
- Built a 171-attack / 102-benign MCP red-team eval gated by a GitHub Actions workflow; found and fixed 4 gaps, raising block rate 93.7% to 97.4% at 0/240 false blocks, p95 7.3 ms.

Keywords this project now honestly proves: MCP (Model Context Protocol) server + client,
tool calling, LLM agent guardrails, prompt-injection defence (OWASP LLM01 / LLM06),
red-team evaluation, eval-gated CI, capability tokens (HMAC), policy-as-code,
hash-chained audit log, Python, FastAPI, pytest.
