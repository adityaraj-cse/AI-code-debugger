"""
Flask Web Application - Code Analyzer Mini Project
Provides a simple browser-based UI: paste code or upload a .py file,
and get back a full visual bug-analysis report.

Run with:  python3 app.py
Then open: http://127.0.0.1:5000
"""

from flask import Flask, request, render_template

from analyzer import analyze_source
from report_generator import build_html_report

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB upload limit


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    filename = "pasted_code.py"
    source_code = ""

    uploaded_file = request.files.get("code_file")
    pasted_code = request.form.get("code_text", "").strip()

    if uploaded_file and uploaded_file.filename:
        filename = uploaded_file.filename
        source_code = uploaded_file.read().decode("utf-8", errors="replace")
    elif pasted_code:
        source_code = pasted_code
    else:
        return render_template(
            "index.html",
            error="Please paste some Python code or upload a .py file."
        )

    try:
        report = analyze_source(source_code, filename=filename)
    except SyntaxError as e:
        return render_template(
            "index.html",
            error=f"Could not parse '{filename}': {e}"
        )

    html_report = build_html_report(report, filename)
    return html_report


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
