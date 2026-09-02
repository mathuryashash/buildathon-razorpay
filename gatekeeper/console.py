"""Make stdout able to print a rupee sign.

Every denial message in this project names an amount in rupees, and on a
default Windows console stdout is cp1252, which has no U+20B9. Printing one
raises UnicodeEncodeError and takes the whole process down -- so `make demo`
died mid-run on Windows while passing on Linux CI.

Called from the three entry points (demo, eval, CLI) rather than executed on
import: a library that reconfigures the caller's stdout as a side effect of
being imported is a nasty surprise, and this is a presentation concern, not a
library one.
"""
from __future__ import annotations

import sys


def use_utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        # errors="replace" rather than "strict": a console that genuinely
        # cannot render the glyph should show a placeholder, never abort a
        # money decision that has already been made and audited.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass  # detached or already-wrapped stream; printing still works
