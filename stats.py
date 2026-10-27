def compute_metrics(issues, total_lines):
    if total_lines == 0:
        total_lines = 1

    bug_density = round(len(issues) / total_lines, 4)

    severity_weights = {"Critical": 15, "High": 10, "Medium": 5, "Low": 2}
    total_penalty = sum(severity_weights.get(issue["severity"], 1) for issue in issues)
    health_score = max(0, round(100 - (total_penalty / total_lines) * 50, 1))

    by_category = {}
    by_severity = {}

    for issue in issues:
        cat = issue["category"]
        sev = issue["severity"]
        by_category[cat] = by_category.get(cat, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total_bugs": len(issues),
        "total_lines": total_lines,
        "bug_density": bug_density,
        "health_score": health_score,
        "by_category": by_category,
        "by_severity": by_severity
    }