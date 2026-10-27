"""
Generates a visual HTML report (with charts) from the analyzer's output.
"""

import os
import base64
from html import escape
from io import BytesIO
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from analyzer import analyze_file


SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#3b82f6",
}
CATEGORY_COLORS = {
    "Security": "#dc2626",
    "Logic": "#f97316",
    "Smell": "#8b5cf6",
    "Style": "#3b82f6",
}


def fig_to_base64(fig):
    buf = BytesIO()
    fig.savefig(buf, format="png", dpi=140, bbox_inches="tight", transparent=True)
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode("utf-8")


def make_pie_chart(data_dict, color_map, title):
    labels = list(data_dict.keys())
    values = list(data_dict.values())
    colors = [color_map.get(l, "#999999") for l in labels]
    fig, ax = plt.subplots(figsize=(4.2, 4.2))
    if values:
        ax.pie(values, labels=labels, autopct="%1.1f%%", colors=colors,
               textprops={"fontsize": 9, "color": "#222"}, startangle=90)
    else:
        ax.text(0.5, 0.5, "No issues found", ha="center", va="center")
        ax.axis("off")
    ax.set_title(title, fontsize=12, fontweight="bold")
    return fig_to_base64(fig)


def make_bar_chart(data_dict, title, ylabel, color="#3b82f6"):
    labels = list(data_dict.keys())
    values = list(data_dict.values())
    fig, ax = plt.subplots(figsize=(6, 3.6))
    bars = ax.bar(labels, values, color=color)
    ax.set_title(title, fontsize=12, fontweight="bold")
    ax.set_ylabel(ylabel, fontsize=9)
    ax.tick_params(axis="x", rotation=25, labelsize=8)
    ax.tick_params(axis="y", labelsize=8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    for bar in bars:
        h = bar.get_height()
        ax.annotate(f"{h:.0f}", (bar.get_x() + bar.get_width() / 2, h),
                    ha="center", va="bottom", fontsize=8)
    fig.tight_layout()
    return fig_to_base64(fig)


def health_color(score):
    if score >= 80:
        return "#16a34a"
    if score >= 60:
        return "#eab308"
    if score >= 40:
        return "#f97316"
    return "#dc2626"


def build_html_report(report, source_filename):
    """Builds the full HTML report and returns it as a string (used by CLI and web UI)."""
    cat_chart = make_pie_chart(report["by_category_count"], CATEGORY_COLORS, "Bug Category Distribution")
    sev_chart = make_pie_chart(report["by_severity_count"], SEVERITY_COLORS, "Bug Severity Distribution")
    func_chart = make_bar_chart(report["by_function_pct"], "Bug Share by Function (%)", "% of total bugs")
    density_chart = make_bar_chart(report["by_function_density_pct"], "Bug Density by Function (%)",
                                    "bugs per LOC (%)", color="#8b5cf6")

    rows = ""
    for b in sorted(report["bugs"], key=lambda x: x["line"]):
        sev_color = SEVERITY_COLORS.get(b["severity"], "#666")
        rows += f"""
        <tr>
            <td class="line-number">{b['line']}</td>
            <td><span class="badge" style="--badge-color:{sev_color}">{escape(str(b['severity']))}</span></td>
            <td>{escape(str(b['category']))}</td>
            <td><code>{escape(str(b['function']))}</code></td>
            <td>{escape(str(b['message']))}</td>
            <td class="fix">{escape(str(b['fix']))}</td>
        </tr>"""

    hcolor = health_color(report["health_score"])
    safe_filename = escape(str(source_filename))
    health_score = report["health_score"]
    total_bugs = report["total_bugs"]
    critical_count = report["by_severity_count"].get("Critical", 0)
    high_count = report["by_severity_count"].get("High", 0)
    function_count = len(report["by_function_count"])
    severity_rows = ""
    for severity in ("Critical", "High", "Medium", "Low"):
        count = report["by_severity_count"].get(severity, 0)
        width = (count / max(total_bugs, 1)) * 100
        color = SEVERITY_COLORS.get(severity, "#64748b")
        severity_rows += (
            f'<div class="severity-row"><span>{escape(severity)}</span>'
            f'<div class="severity-track"><div class="severity-fill" '
            f'style="--severity-width:{width:.1f}%;--severity-color:{color}">'
            f'</div></div><span class="severity-count">{count}</span></div>'
        )
    finding_label = "finding" if total_bugs == 1 else "findings"
    findings_html = (
        '<div class="empty-state">✓ No issues found — your code looks clean.</div>'
        if not rows
        else (
            '<div class="table-scroll"><table><thead><tr><th>Line</th>'
            '<th>Severity</th><th>Category</th><th>Function</th>'
            '<th>Finding</th><th>Suggested fix</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#091333">
<title>Code Health Dashboard - {safe_filename}</title>
<style>
  :root {{ --navy:#091333; --ink:#111a35; --muted:#758099; --line:#e7ebf2; --surface:#fff; }}
  * {{ box-sizing:border-box; }}
  html {{ scroll-behavior:smooth; }}
  body {{ margin:0; color:var(--ink); background:#f5f7fb; font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }}
  .app-shell {{ min-height:100vh; display:grid; grid-template-columns:224px minmax(0,1fr); }}
  .sidebar {{ position:sticky; top:0; height:100vh; padding:23px 14px; color:#bac4dc; background:var(--navy); }}
  .brand {{ display:flex; align-items:center; gap:10px; padding:0 10px 28px; color:white; font-size:16px; font-weight:800; letter-spacing:-.04em; }}
  .brand-mark {{ width:29px; height:29px; display:grid; place-items:center; border-radius:8px; color:white; background:linear-gradient(135deg,#0bbf9a,#249ce5); }}
  .side-label {{ padding:9px 10px 7px; color:#73809f; font-size:9px; font-weight:800; letter-spacing:.13em; text-transform:uppercase; }}
  .side-link {{ display:flex; align-items:center; gap:10px; margin:3px 0; padding:10px; border-radius:8px; color:#bac4dc; font-size:12px; font-weight:600; }}
  .side-link.active {{ color:var(--navy); background:#fff; }}
  .side-icon {{ width:17px; text-align:center; font-size:14px; }}
  .sidebar-bottom {{ position:absolute; right:14px; bottom:17px; left:14px; padding:12px; border:1px solid #1d2b51; border-radius:9px; color:#99a7c7; font-size:10px; line-height:1.55; }}
  .sidebar-bottom strong {{ display:block; margin-bottom:3px; color:white; font-size:11px; }}
  .main {{ min-width:0; padding:29px clamp(18px,4vw,48px) 48px; }}
  .topbar {{ display:flex; justify-content:space-between; align-items:center; gap:16px; margin-bottom:24px; }}
  .breadcrumbs {{ color:var(--muted); font-size:11px; }}
  .top-actions {{ display:flex; align-items:center; gap:9px; }}
  .file-pill,.status-pill {{ padding:8px 11px; border:1px solid var(--line); border-radius:8px; background:white; font-size:10px; }}
  .file-pill {{ max-width:260px; overflow:hidden; color:#59657d; text-overflow:ellipsis; white-space:nowrap; }}
  .status-pill {{ border-color:#cceee4; color:#11866e; background:#effbf7; font-weight:800; }}
  .page-heading {{ display:flex; justify-content:space-between; align-items:flex-end; gap:16px; margin-bottom:18px; }}
  h1 {{ margin:0 0 5px; font-size:25px; letter-spacing:-.045em; }}
  .subtitle {{ color:var(--muted); font-size:12px; }}
  .section-label {{ margin:24px 0 11px; font-size:13px; font-weight:800; letter-spacing:-.01em; }}
  .metric-grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }}
  .metric {{ min-height:105px; padding:15px; border:1px solid var(--line); border-radius:11px; background:var(--surface); box-shadow:0 2px 6px rgba(18,34,65,.025); }}
  .metric-label {{ display:flex; justify-content:space-between; align-items:center; gap:8px; color:#6f7a91; font-size:10px; font-weight:700; }}
  .metric-symbol {{ width:25px; height:25px; display:grid; place-items:center; border-radius:7px; color:#149980; background:#e9faf5; font-size:13px; }}
  .metric:nth-child(2) .metric-symbol {{ color:#d18b12; background:#fff6e3; }}
  .metric:nth-child(3) .metric-symbol {{ color:#d35454; background:#fff0ef; }}
  .metric:nth-child(4) .metric-symbol {{ color:#4386dc; background:#edf5ff; }}
  .metric-value {{ margin-top:10px; color:var(--ink); font-size:25px; font-weight:800; letter-spacing:-.05em; }}
  .metric-note {{ margin-top:2px; color:#8993a6; font-size:9px; }}
  .overview-grid {{ display:grid; grid-template-columns:minmax(0,1.7fr) minmax(220px,.8fr); gap:13px; }}
  .health-panel {{ min-height:177px; display:grid; grid-template-columns:145px 1fr; align-items:center; gap:16px; padding:20px; border-radius:12px; color:white; background:linear-gradient(130deg,#091333,#172653); box-shadow:0 8px 20px rgba(9,19,51,.12); }}
  .health-ring {{ width:116px; height:116px; display:grid; place-items:center; border-radius:50%; background:conic-gradient({hcolor} {health_score}%,#26365e 0); }}
  .health-ring-inner {{ width:94px; height:94px; display:grid; place-content:center; border:5px solid #101d40; border-radius:50%; background:#111e42; text-align:center; }}
  .health-ring strong {{ font-size:25px; line-height:1; }}
  .health-ring small {{ margin-top:5px; color:#aab5d0; font-size:8px; }}
  .health-copy h2 {{ margin:0 0 6px; font-size:14px; }}
  .health-copy p {{ margin:0; color:#aab5d0; font-size:10px; line-height:1.6; }}
  .health-meta {{ display:flex; flex-wrap:wrap; gap:8px; margin-top:13px; }}
  .health-meta span {{ padding:5px 8px; border:1px solid #31416a; border-radius:6px; color:#d5dced; font-size:9px; }}
  .severity-panel {{ padding:17px; border:1px solid var(--line); border-radius:11px; background:white; }}
  .panel-title {{ display:flex; justify-content:space-between; align-items:center; gap:10px; margin:0 0 14px; font-size:12px; font-weight:800; }}
  .panel-title small {{ color:#8a94a8; font-size:9px; font-weight:600; }}
  .severity-row {{ display:grid; grid-template-columns:54px 1fr 22px; align-items:center; gap:8px; margin:12px 0; color:#68748b; font-size:9px; }}
  .severity-track {{ height:6px; overflow:hidden; border-radius:99px; background:#f0f2f6; }}
  .severity-fill {{ height:100%; width:var(--severity-width); border-radius:inherit; background:var(--severity-color); }}
  .severity-count {{ color:var(--ink); text-align:right; font-weight:800; }}
  .chart-grid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:13px; }}
  .chart-card {{ min-width:0; padding:14px; border:1px solid var(--line); border-radius:11px; background:white; }}
  .chart-card img {{ display:block; width:100%; max-height:250px; object-fit:contain; }}
  .table-card {{ overflow:hidden; border:1px solid var(--line); border-radius:11px; background:white; }}
  .table-head {{ display:flex; justify-content:space-between; align-items:center; gap:12px; padding:15px 16px; border-bottom:1px solid var(--line); }}
  .table-head strong {{ font-size:12px; }}
  .table-head span {{ color:var(--muted); font-size:10px; }}
  .table-scroll {{ overflow-x:auto; }}
  table {{ width:100%; min-width:760px; border-collapse:collapse; }}
  th,td {{ padding:11px 12px; border-bottom:1px solid #edf0f5; text-align:left; vertical-align:top; font-size:10px; line-height:1.5; }}
  th {{ color:#778299; background:#fafbfd; font-size:9px; font-weight:800; letter-spacing:.04em; text-transform:uppercase; }}
  tbody tr:last-child td {{ border-bottom:0; }}
  .line-number {{ color:#71809a; font-variant-numeric:tabular-nums; }}
  .badge {{ display:inline-block; padding:4px 7px; border-radius:99px; color:var(--badge-color); background:color-mix(in srgb,var(--badge-color) 12%,white); font-size:9px; font-weight:800; }}
  td code {{ color:#53617c; font-size:9px; }}
  .fix {{ min-width:190px; color:#59657d; }}
  .empty-state {{ padding:25px; color:#168a78; text-align:center; font-size:12px; font-weight:700; }}
  .back-link {{ color:#45617e; font-size:10px; font-weight:700; }}
  @media(max-width:950px) {{ .app-shell {{ grid-template-columns:70px minmax(0,1fr); }} .sidebar {{ padding-right:8px; padding-left:8px; }} .brand {{ justify-content:center; padding-right:0; padding-left:0; font-size:0; }} .brand-mark {{ font-size:15px; }} .side-label,.side-link span:not(.side-icon),.sidebar-bottom {{ display:none; }} .side-link {{ justify-content:center; padding:11px 5px; }} .metric-grid {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} }}
  @media(max-width:620px) {{ .app-shell {{ display:block; }} .sidebar {{ position:static; height:58px; display:flex; align-items:center; padding:8px 12px; }} .brand {{ justify-content:flex-start; padding:0; font-size:15px; }} .brand-mark {{ font-size:15px; }} .sidebar nav {{ display:flex; gap:3px; margin-left:auto; }} .side-link {{ width:36px; margin:0; }} .main {{ padding:20px 14px 32px; }} .topbar {{ align-items:flex-start; }} .top-actions {{ flex-direction:column; align-items:flex-end; }} .page-heading {{ align-items:flex-start; }} h1 {{ font-size:21px; }} .metric-grid {{ gap:8px; }} .metric {{ min-height:97px; padding:12px; }} .metric-value {{ font-size:22px; }} .overview-grid,.chart-grid {{ grid-template-columns:1fr; }} .health-panel {{ grid-template-columns:105px 1fr; gap:12px; padding:14px; }} .health-ring {{ width:96px; height:96px; }} .health-ring-inner {{ width:78px; height:78px; }} .health-ring strong {{ font-size:21px; }} }}
</style>
</head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="/"><span class="brand-mark">⌘</span>CodeLens</a>
    <nav aria-label="Dashboard navigation">
      <div class="side-label">Workspace</div>
      <a class="side-link active" href="#overview"><span class="side-icon">▦</span><span>Overview</span></a>
      <a class="side-link" href="#code-health"><span class="side-icon">◉</span><span>Code health</span></a>
      <a class="side-link" href="#security"><span class="side-icon">◇</span><span>Security posture</span></a>
      <a class="side-link" href="#findings"><span class="side-icon">≡</span><span>Findings</span></a>
    </nav>
    <div class="sidebar-bottom"><strong>Static analysis</strong>Results are heuristic signals. Review findings in context before changing your code.</div>
  </aside>
  <main class="main">
    <div class="topbar">
      <div class="breadcrumbs">Workspace &nbsp;›&nbsp; Analysis &nbsp;›&nbsp; Overview</div>
      <div class="top-actions"><span class="file-pill" title="{safe_filename}">Python file · {safe_filename}</span><span class="status-pill">● Scan complete</span></div>
    </div>
    <section id="overview">
      <div class="page-heading"><div><h1>Code health overview</h1><div class="subtitle">Analysis summary and actionable findings for this scan.</div></div><a class="back-link" href="/">← Analyze another file</a></div>
      <div class="metric-grid">
        <article class="metric"><div class="metric-label">Total findings <span class="metric-symbol">≡</span></div><div class="metric-value">{total_bugs}</div><div class="metric-note">Across all detected categories</div></article>
        <article class="metric"><div class="metric-label">High &amp; critical <span class="metric-symbol">△</span></div><div class="metric-value">{high_count + critical_count}</div><div class="metric-note">Critical issues: {critical_count}</div></article>
        <article class="metric"><div class="metric-label">Critical issues <span class="metric-symbol">!</span></div><div class="metric-value">{critical_count}</div><div class="metric-note">Review these findings first</div></article>
        <article class="metric"><div class="metric-label">Functions flagged <span class="metric-symbol">ƒ</span></div><div class="metric-value">{function_count}</div><div class="metric-note">Functions with one or more findings</div></article>
      </div>
    </section>
    <div class="section-label" id="code-health">Code quality</div>
    <section class="overview-grid">
      <div class="health-panel">
        <div class="health-ring"><div class="health-ring-inner"><strong>{health_score}</strong><small>HEALTH / 100</small></div></div>
        <div class="health-copy"><h2>Code health score</h2><p>A severity-weighted summary of the issues found in this file. Use it as a guide, then review each finding below.</p><div class="health-meta"><span>{total_bugs} findings</span><span>{function_count} functions flagged</span></div></div>
      </div>
      <div class="severity-panel" id="security">
        <div class="panel-title">Findings by severity <small>COUNT</small></div>
        {severity_rows}
      </div>
    </section>
    <div class="section-label">Issue distribution</div>
    <section class="chart-grid">
      <article class="chart-card"><div class="panel-title">Findings by category <small>SHARE</small></div><img alt="Findings by category chart" src="data:image/png;base64,{cat_chart}"></article>
      <article class="chart-card"><div class="panel-title">Findings by severity <small>SHARE</small></div><img alt="Findings by severity chart" src="data:image/png;base64,{sev_chart}"></article>
      <article class="chart-card"><div class="panel-title">Bug share by function <small>PERCENT</small></div><img alt="Bug share by function chart" src="data:image/png;base64,{func_chart}"></article>
      <article class="chart-card"><div class="panel-title">Bug density by function <small>BUGS / LOC</small></div><img alt="Bug density by function chart" src="data:image/png;base64,{density_chart}"></article>
    </section>
    <div class="section-label" id="findings">Detailed findings</div>
    <section class="table-card">
      <div class="table-head"><strong>Analysis results</strong><span>{total_bugs} {finding_label} · Sorted by source line</span></div>
      {findings_html}
    </section>
  </main>
</div>
</body>
</html>"""

    return html


def generate_html_report(report, source_filename, out_path):
    """Builds the report and writes it to a file (used by the command-line script)."""
    html = build_html_report(report, source_filename)
    with open(out_path, "w") as f:
        f.write(html)
    return out_path


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "sample_buggy_code.py"
    report = analyze_file(target)
    out = generate_html_report(report, os.path.basename(target), "report.html")
    print(f"Report generated: {out}")
