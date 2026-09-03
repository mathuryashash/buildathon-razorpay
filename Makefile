# Every number in the README is produced by `make eval`. If you change a rule
# and do not re-run this, the README is lying.

.PHONY: help install test eval eval-holdout demo preflight live visualiser serve merchant verify lint clean

help:
	@echo "make install       install dependencies"
	@echo "make test          run the unit tests (fast, no network)"
	@echo "make eval          run the red-team evaluation -> the README numbers"
	@echo "make eval-holdout  ALSO run the sealed hold-out set. ONCE, after freeze."
	@echo "make demo          the pitch demo: same agent, with and without the proxy"
	@echo "                   add QUIET=1 for verdicts only, without the reasoning"
	@echo "make preflight     check your Razorpay test key works, create nothing"
	@echo "make live          the live run against real Razorpay TEST MODE"
	@echo "make visualiser    regenerate visualiser.html from a live run"
	@echo "make serve         run the proxy on :8080"
	@echo "make merchant      run the reference merchant on :8081"
	@echo "make verify        check the audit chain for tampering"

install:
	pip install -r requirements.txt

test:
	python -m pytest tests -q

eval:
	python evals/run_eval.py --json eval_results.json

eval-holdout:
	@echo "The hold-out set is meant to be run ONCE, after code freeze."
	@echo "Publish whatever it says. See docs/DO_NOT_BUILD.md item 1."
	python evals/run_eval.py --holdout --json eval_results.json

demo:
	python demo.py $(if $(QUIET),--quiet,)

preflight:
	python live.py --preflight

live:
	python live.py

# visualiser.html ships with real trace data baked in. This re-bakes it.
#
# It runs the eval WITH the hold-out, because the page reports the held-out
# score and a plain `make eval` writes a results file with that field null --
# which would quietly blank the one number on the page that carries weight.
#
# Re-running a hold-out is not a protocol breach. The set is deterministic and
# the code is frozen, so it reproduces 15/21 every time. The rule it must not
# break is EDITING A RULE after seeing the result, which is what would make the
# score meaningless. See docs/DO_NOT_BUILD.md item 1.
visualiser:
	python evals/run_eval.py --holdout --json eval_results.json
	python tools/build_visualiser.py

serve:
	python -m gatekeeper serve --backend $(or $(BACKEND),mock)

merchant:
	python -m uvicorn merchant.app:app --port 8081

verify:
	python -m gatekeeper verify

lint:
	ruff check . || true

clean:
	rm -f *.db eval_results.json
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
