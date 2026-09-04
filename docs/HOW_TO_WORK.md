# How To Work On This

The companion to `DO_NOT_BUILD.md`. That file says what to avoid; this one says
what to do and how to do it, in order.

---

## Setup (10 minutes, do this first)

```bash
git clone https://github.com/mathuryashash/buildathon-razorpay.git
cd buildathon-razorpay

python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # paste into GATEKEEPER_SIGNING_SECRET
# paste your rzp_test_ key id and secret into .env as well

make preflight   # confirms the key works before anything is created with it

make test        # the full suite, seconds, no network
make eval        # the red-team numbers
make demo        # the pitch demo
```

If `make test` is green and `make demo` prints two different money totals, the
project works. That is the whole smoke test.

> **Rotate your Razorpay test key if it has ever been pasted into a chat, an
> issue, or a screenshot.** Dashboard → Settings → API Keys → Regenerate Test
> Key. A test key still identifies your account and can create real records on
> it. Rotating costs thirty seconds.

---

## The loop, every time you change something

```bash
make test && make eval && make demo
```

All three, in that order, every time. They take under five seconds combined.
`make eval` exits non-zero if the attack corpus is not fully blocked, so CI
catches a rule change that quietly reopens a hole.

**If `make eval` reports failures, read them before you change anything.** Two
of the three real bugs found during this build were surfaced by the *benign*
corpus, not the attack corpus — the firewall was blocking legitimate traffic
and only the false-block number showed it. That is what the second corpus is
for. Do not "fix" a failure by editing the expectation until you have worked
out whether the code or the expectation is wrong, and record which it was.

---

## How to add a policy rule (the most common change)

Six steps, in this order. Skipping step 1 or step 5 is how the rule set rots.

**1. Add the threat to `THREAT_MODEL.md` first**, with an ID (`T8`, `T9`…).
   If you cannot write one sentence naming what goes wrong without this rule,
   stop — the rule is not justified yet.

**2. Add the rule to `policies/default.yaml`**, citing that threat ID:

```yaml
  - id: DEST-002
    threat: T4
    description: One sentence. What this stops, in a merchant's words.
    when:
      effect_in: [irreversible_money]
      amount_paise_gt: 100000
    action: deny
    explain: >-
      Blocked: {amount} to {counterparty} exceeds ...
```

   Available conditions are in `CONDITIONS` in `gatekeeper/policy.py`. All
   conditions in a `when` block are ANDed; there is no OR — write two rules.
   Do not add an expression evaluator (`DO_NOT_BUILD.md` item 3).

**3. Write the `explain` string for a merchant, not an engineer.**
   Bad: `Denied by DEST-002 (amount_paise_gt).`
   Good: `Blocked: this would be the 4th charge to Priya in 10 minutes; your limit is 3.`
   The placeholders available are listed in `Rule.render`. A verdict a person
   cannot act on is traceability, not explainability.

**4. Add an attack scenario** to `evals/scenarios/attacks.yaml` that the rule blocks.

**5. Add a benign scenario** to `evals/scenarios/benign.yaml` that it must NOT
   block — including a **boundary case exactly at the threshold.** Off-by-one
   at a cap blocks a real customer, so it gets its own scenario every time.

**6. Add a unit test** in `tests/test_policy.py` if the rule has interesting
   interaction with another rule (precedence, windows, counterparty scoping).

Then run the loop.

## How to add a proxied operation

1. Classify it in `policies/effects.yaml` under exactly one effect class.
   Ask: *can this move money in a way that needs a second money movement to
   undo?* If yes it is `irreversible_money`, whatever the API docs call it.
   Getting this wrong is the highest-severity mistake available — a
   `create_refund` filed as `reversible_write` defeats every money cap at once.
2. Implement it in `MockBackend.call` with a Razorpay-shaped response.
3. Implement it in `RazorpayBackend.call` if the demo needs it live.
4. Add it to `GRANTED` in `evals/run_eval.py` only if the eval agent should
   have it. Leaving an op out is itself a useful test of the scope check.
5. Add a benign scenario exercising it.

## How to change the demo

`demo.py` is what the video records. Its job is one sentence: *same agent, same
prompt, different outcome.* Keep the plan in `AGENT_PLAN` short enough that the
output fits one terminal screen without scrolling — a reviewer watching a video
cannot scroll back.

---

## Working with the live Razorpay backend

```bash
make live               # or: python -m gatekeeper serve --backend razorpay
```

Notes from building against test mode:

- **Orders and Payment Links work fully in test mode** and are the right things
  to show live. `create_order` and `create_payment_link` both return real
  objects with real ids, and the link's `short_url` opens a real test checkout.
- **Capture and refund need an actually-authorised payment**, which needs a
  human to complete a checkout. Not scriptable for a demo. Use the mock backend
  for those paths and say so.
- **The backend refuses any key not starting `rzp_test_`.** That is deliberate
  (`backends.py`). Do not "temporarily" relax it.
- **Test mode cannot generate batches.** Subscription charge failures are a
  Dashboard button, Smart Collect test payments are a Dashboard action, and
  there is no dispute-creation API. This is exactly why the eval runs against
  the mock backend: 67 deterministic calls, offline, reproducible.

## Running the two services separately

```bash
make merchant           # reference merchant on :8081
make serve              # proxy on :8080

python -m gatekeeper issue-token --agent-id buyer-1 \
    --scopes fetch_catalog,create_order,create_payment_link
python -m gatekeeper log        # read the audit trail
python -m gatekeeper verify     # check the chain
```

---

## Commit discipline

Real history matters here — the repo is the resume, and a single
`initial commit` with 40 files reads as a dump.

- Small commits, present tense: `add velocity rule for repeated counterparty charges`
- **Commit the failures too.** The commit where the benign corpus caught the
  velocity double-count is more interesting to a reviewer than the fix.
- Never amend away a commit that contained a secret — rotate the key instead.
- Do not force-push `main`.

## Before you submit

```bash
make clean && make test && make eval && make demo
git status                        # must be clean; no .env, no *.db
grep -rn "rzp_test_[A-Za-z0-9]" --exclude-dir=.git .   # must return nothing
```

Then, in order:
1. Freeze the code.
2. Write `evals/scenarios/holdout.yaml` (5 scenarios, no peeking at the rules).
3. `make eval-holdout` — **once**.
4. Put the real number in the README, whatever it is.
5. Record the video (`docs/DEMO_SCRIPT.md`).
6. Fill the form (`docs/SUBMISSION.md`).

Submit on the 4th. Not the 5th.
