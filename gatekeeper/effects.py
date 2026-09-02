"""Static effect classification with deny-by-default on unknown operations.

This is the smallest and most important module in the project. The rule it
enforces is a single line of logic, and it is the reason an unreviewed tool
cannot move money:

    an operation with no declared effect class is DENIED.

Most agent frameworks do the opposite -- they expose whatever tools are
registered and rely on the prompt to keep the model in line. A prompt is not
a control.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from .models import Effect

DEFAULT_PATH = Path(__file__).resolve().parent.parent / "policies" / "effects.yaml"


class EffectRegistry:
    def __init__(self, mapping: dict[str, Effect]):
        self._map = mapping

    @classmethod
    def load(cls, path: Path | str | None = None) -> "EffectRegistry":
        p = Path(path) if path else DEFAULT_PATH
        raw = yaml.safe_load(p.read_text()) or {}
        mapping: dict[str, Effect] = {}
        for effect_name, ops in (raw.get("operations") or {}).items():
            effect = Effect(effect_name)
            for op in ops or []:
                if op in mapping:
                    raise ValueError(f"operation {op!r} declared twice in {p}")
                mapping[op] = effect
        return cls(mapping)

    def classify(self, op: str) -> Effect | None:
        """Return the declared effect, or None if the operation is unknown.

        None is not 'no effect'. None means 'undeclared', and the policy engine
        turns undeclared into a denial.
        """
        return self._map.get(op)

    def known_operations(self) -> list[str]:
        return sorted(self._map)

    def __len__(self) -> int:
        return len(self._map)
