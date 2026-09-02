# 5-Minute Pitch Video Script

Unlisted YouTube is fine. Record in one take if you can — a slightly rough
single take reads as more honest than a polished edit, and it is faster.

**Structure: 60s problem · 90s demo · 90s numbers · 60s limits.**
The limits section is what makes the first three credible. Do not cut it.

---

## 0:00–1:00 — The problem

> "Razorpay already ships agentic payments. In-app commerce, UPI Reserve Pay,
> an MCP server with forty-five tools. So the question isn't whether an AI
> agent can pay any more.
>
> It's what stops one that's been prompt-injected — or has just gone wrong.
>
> Here's the thing about that agent: it usually isn't malicious. It's obedient.
> It reads a product description with an injected instruction in it and does
> what it's told. You can't fix that with a better system prompt, because the
> attack arrives *through* the prompt.
>
> Today a merchant's only options are: give the agent API keys, or don't.
> I built the middle position."

## 1:00–2:30 — The demo

Terminal, full screen, font large enough to read on a phone. `make demo`.

> "Same agent, twice. First run it talks to the payments API directly.
> It creates a legitimate order — then it hits the injected instructions.
> Twenty-five hundred rupees to an account the merchant has never seen.
> Five thousand out as a payout. Then it just loops.
> Nine thousand nine hundred and fifty rupees gone. Nothing stopped it.
>
> Second run. Identical agent, identical prompt. Now it's behind Gatekeeper.
> The refund is blocked — over the per-action cap. The payout is blocked.
> The loop gets three actions in before velocity catches it. And this one —"

*(point at `transfer_all_funds`)*

> "— this one is my favourite. That operation has no declared effect class,
> so it's denied by default. Registering a new tool can't silently widen what
> an agent is allowed to do.
>
> Every line has a reason a merchant can read. The chain is intact."

## 2:30–4:00 — The numbers

> "The agent holds no Razorpay credential. At all. It gets a scoped,
> short-lived capability token; the proxy holds the key. That matters, because
> a proxy the agent can go around enforces nothing — and there's a test that
> fails the build if a credential ever appears in the agent package.
>
> Fifty-two scenarios, a hundred and forty-five calls. A hundred percent block rate on the
> attack corpus — and zero percent false blocks on the benign one.
>
> That second number is the one I care about. A firewall that denies everything
> scores a hundred percent block rate. The harness prints a deny-everything
> baseline every single run so I can't quote one without the other.
>
> Two point one milliseconds median."

## 4:00–5:00 — What's wrong with it

> "Three things you should know before you believe any of that.
>
> One: the hundred percent is in-sample. I wrote the attacks and I wrote the
> rules. That proves I'm internally consistent, not that this is any good.
> The hold-out set is sealed — five scenarios written after code freeze, run
> once, and I publish whatever comes out.
>
> Two: two policy bugs shipped and the eval caught them, not me. The worse one
> double-counted a single purchase against the spend window, so a five thousand
> rupee payment link could never be created at all. The *benign* corpus found
> it while every attack test passed. Without that second corpus this ships as
> a hundred percent block rate and a product nobody can use. Both are written
> up as ADRs.
>
> Three: if the agent gets a credential some other way, the proxy is bypassed
> and none of this applies. That's the honest ceiling of the design, and it's
> in the threat model as a non-goal.
>
> Razorpay ships the checkout. Nobody ships the thing that proves the checkout
> holds. That's what this is."

---

## Recording notes

- **Terminal only.** No slides. The output is the artifact.
- Increase font size before recording. A reviewer may watch on a phone.
- `make clean` first so the demo starts from an empty audit log.
- Do not narrate over silence while something loads — cut it.
- Say "rupees", not "INR".
- If you fluff a line, keep going. One take at 95% beats four takes at 100%.

## Do not

- Do not claim the hold-out number before you have run it
- Do not say "production ready"
- Do not read the README aloud
- Do not spend a minute on the reference merchant — nobody cares, and correctly
