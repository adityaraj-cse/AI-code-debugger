import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import os

def make_charts(metrics, category_img_path="static/cat_chart.png", severity_img_path="static/sev_chart.png"):
    os.makedirs("static", exist_ok=True)

    category_fig, category_ax = plt.subplots(figsize=(4, 3))
    if metrics["by_category"]:
        category_ax.pie(
            metrics["by_category"].values(),
            labels=metrics["by_category"].keys(),
            autopct="%1.0f%%",
        )
    else:
        category_ax.text(0.5, 0.5, "No issues found", ha="center", va="center")
        category_ax.axis("off")
    category_ax.set_title("Bugs by Category")
    category_fig.tight_layout()
    category_fig.savefig(category_img_path)
    plt.close(category_fig)

    severity_fig, severity_ax = plt.subplots(figsize=(4, 3))
    if metrics["by_severity"]:
        colors = {"Critical": "red", "High": "orange", "Medium": "gold", "Low": "skyblue"}
        severities = metrics["by_severity"]
        bar_colors = [colors.get(severity, "gray") for severity in severities]
        severity_ax.bar(severities.keys(), severities.values(), color=bar_colors)
    else:
        severity_ax.text(0.5, 0.5, "No issues found", ha="center", va="center")
        severity_ax.axis("off")
    severity_ax.set_title("Bugs by Severity")
    severity_fig.tight_layout()
    severity_fig.savefig(severity_img_path)
    plt.close(severity_fig)