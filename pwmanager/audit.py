"""Vault health check: weak, reused, old and personal passwords."""

import hashlib
from collections import defaultdict
from datetime import datetime

from .strength import analyse

OLD_AFTER_DAYS = 365
FAIR_SCORE = 2


def health_report(vault):
    """Return a dict with issue lists, a 0-100 health score and per-entry details."""
    entries = vault.list()
    now = vault.now()
    by_password = defaultdict(list)
    weak, fair, old, personal, rows = [], [], [], [], []
    for e in entries:
        # group by a hash so the report itself never needs to compare or keep plain passwords
        by_password[hashlib.sha256(e.password.encode("utf-8")).hexdigest()].append(e)
        s = analyse(e.password, user_inputs=(e.site, e.username))
        age = (now - datetime.fromisoformat(e.updated)).days if e.updated else 0
        if s.score < FAIR_SCORE:
            weak.append(e)
        elif s.score == FAIR_SCORE:
            fair.append(e)
        if age >= OLD_AFTER_DAYS:
            old.append(e)
        if any("your name, username or the site" in w for w in s.warnings):
            personal.append(e)
        rows.append({"entry": e, "score": s.score, "label": s.label, "age_days": age})
    reused = [group for group in by_password.values() if len(group) > 1]
    reused_ids = {e.entry_id for group in reused for e in group}

    problem_ids = {e.entry_id for e in weak + old + personal} | reused_ids
    total = len(entries)
    if total:
        # weak and reused passwords are serious; fair and old are minor
        penalty = sum(1.0 for e in weak) + sum(1.0 for _ in reused_ids) + 0.4 * len(fair) + 0.3 * len(old)
        score = max(0, round(100 * (1 - penalty / (2 * total))))
    else:
        score = 100
    grade = "Excellent" if score >= 90 else "Good" if score >= 75 else "Needs attention" if score >= 50 else "Poor"
    return {"total": total, "healthy": total - len(problem_ids), "score": score, "grade": grade,
            "weak": weak, "fair": fair, "reused": reused, "old": old, "personal": personal, "rows": rows}


def category_counts(vault):
    counts = defaultdict(int)
    for e in vault.list():
        for tag in e.tags or ["(no tag)"]:
            counts[tag] += 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))
