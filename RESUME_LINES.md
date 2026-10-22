# Resume lines (numbers from VERIFY.md only)

- Built Gatekeeper, an MCP server (official Python SDK, stdio + streamable-HTTP) that puts a fail-closed policy engine between LLM agents and a Razorpay-style payments API; a live Groq gpt-oss-120b agent attempted 4 prompt-injected attacker refunds and 0 executed.
- Built a 171-attack / 102-benign MCP red-team eval gated in CI; found and fixed 5 gaps, raising the block rate from 93.7% to 97.9% at 0/240 benign false blocks. On a blind hold-out written by a separate model that never saw the rules, it scored 21/28 (8/9 attack calls blocked).

Keywords this project honestly supports: MCP (Model Context Protocol) server + client,
tool calling, LLM agent guardrails, prompt-injection defence (OWASP LLM01 / LLM06),
red-team and blind hold-out evaluation, eval-gated CI, capability tokens (HMAC),
policy-as-code, hash-chained audit log, Python, FastAPI, pytest.
