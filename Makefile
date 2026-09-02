# Every number in the README is produced by `make eval`. If you change a rule
# and do not re-run this, the README is lying.

.PHONY: help install test eval eval-holdout demo demo-live serve merchant verify lint clean

help:
	@echo "make install       install dependencies"
	@echo "make test          run the unit tests (fast, no network)"
	@echo "make eval          run the red-team evaluation -> the README numbers"
	@echo "make eval-holdout  ALSO run the sealed hold-out set. ONCE, after freeze."
	@echo "make demo          the pitch demo: same agent, with and without the proxy"
	@echo "make demo-live     the same demo, hitting real Razorpay TEST MODE"
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
	python demo.py

demo-live:
	python demo.py --live

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
