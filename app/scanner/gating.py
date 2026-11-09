"""Who gets the fixes.

A scan has two parts: the findings (what is wrong, how badly, and why it
matters) and the solutions (the exact records to publish and the step-by-step
fix guides). Findings are free for everyone. Solutions are for signed-in
accounts only, and that is enforced here, on the server, for every way a scan
leaves the app: API responses, shared report pages and PDFs. Hiding them in
the browser alone would not count, because the JSON would still carry them.
"""
import copy

# Fields on a check that tell the reader how to fix it.
SOLUTION_FIELDS = ("fixes", "guide")


def fixable(check: dict) -> bool:
    return check.get("status") in ("fail", "warn") and bool(check.get("fixes") or check.get("guide"))


def lock_check(check: dict) -> dict:
    """A single check with its solutions removed (a copy)."""
    out = {k: v for k, v in check.items() if k not in SOLUTION_FIELDS}
    out["fixes"] = []
    out["solutions_locked"] = fixable(check)
    return out


def findings_only(result: dict | None) -> dict | None:
    """A scan result without any solutions: the free report."""
    if not result:
        return result
    out = copy.deepcopy(result)
    checks = out.get("checks") or []
    out["locked_fixes"] = sum(1 for c in checks if fixable(c))
    out["checks"] = [lock_check(c) for c in checks]
    # Keep the priority order (which checks to fix first, and what each is
    # worth), not how to fix them.
    out["action_plan"] = [{"check": p.get("check"), "points": p.get("points")}
                          for p in out.get("action_plan") or []]
    out["solutions_locked"] = True
    return out
