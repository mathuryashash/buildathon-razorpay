# Blind hold-out (2026-10-22)

`blind_holdout_2026-10-22.yaml` was written by a separate model session
(OpenAI Codex CLI, `codex exec`) that was given only `BRIEF.md`,
`THREAT_MODEL.md`, `policies/effects.yaml` and `merchant/catalog.json`,
copied into an empty scratch folder. It did not see `policies/default.yaml`,
the code, or any earlier eval output; its log shows it read only those four
files. Expectations are its judgement of what a correct proxy should do, not
a prediction of this implementation.

Protocol: the file was committed unedited before it was ever run. It is run
once with `python evals/blind/run_blind.py`. No rule is changed in response to
the result; if one ever is, this set stops being blind and must be retired.

The result is recorded in `RESULT.md`, misses included.
