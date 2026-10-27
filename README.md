# Code Analyzer — Mini Project

AST-based static code analyzer for Python that detects bugs, security risks,
and code smells — then shows **where** the bugs are concentrated (function-wise
% share and bug-density) with an auto-generated visual HTML report.

## Project Structure

```
code_analyzer_project/
├── app.py                  # Flask web application (main entry point)
├── analyzer.py             # Core AST-based bug detection engine
├── report_generator.py     # Chart generation + HTML report builder
├── sample_buggy_code.py    # Sample file with intentional bugs (for demo/testing)
├── templates/
│   └── index.html          # Upload / paste-code web page
├── requirements.txt
└── README.md
```

## How It Works

1. **Parsing** — `analyzer.py` parses the given Python source using the built-in
   `ast` module, which turns code into a tree structure (the same technique the
   Python compiler itself uses).
2. **Detection** — Custom `ast.NodeVisitor` checks walk the tree and flag:
   - **Security**: hardcoded credentials, dynamically built SQL, `eval`/`exec`,
     unsafe `pickle` loading, and subprocess calls using `shell=True`
   - **Logic**: broad or bare exception handlers and mutable default arguments
   - **Smells**: overly long functions and deeply nested `if` blocks
   - **Style**: unused variables/imports, incorrect `None` comparisons, and
     identity comparisons against non-singleton values
   - Each finding includes a source line and a suggested fix. The analyzer is
     static and heuristic: it highlights common issues but cannot guarantee
     detection of every runtime bug or prove that a flagged pattern is exploitable.
3. **Distribution Analysis** — bugs are aggregated by function, category, and
   severity, and converted into:
   - `% share` — what fraction of all bugs come from this function/category
   - `density %` — bugs per line of code, so small and large functions are
     compared fairly
   - an overall **Code Health Score** (0–100)
4. **Reporting** — `report_generator.py` turns the results into pie/bar charts
   (Matplotlib) embedded in a styled HTML report with a full bug table and
   suggested fixes.
5. **Web UI** — `app.py` (Flask) lets you paste code or upload a `.py` file in
   the browser and view the report instantly.

## Setup

```bash
pip install -r requirements.txt
```

## Running

### Option A — Web UI (recommended for demo)
```bash
python3 app.py
```
Then open **http://127.0.0.1:5000** in your browser, paste code or upload a
`.py` file, and click "Analyze Code".

### Option B — Command line
```bash
python3 report_generator.py sample_buggy_code.py
```
This generates `report.html` in the same folder — open it in any browser.

You can also run the analyzer directly for a text summary in the terminal:
```bash
python3 analyzer.py sample_buggy_code.py
```

## Testing It

`sample_buggy_code.py` is included with several intentional bugs (hardcoded
password, SQL injection pattern, bare except, mutable default argument,
unused variables, deep nesting, long function) so you always have something
to demo with.

Run the analyzer's focused regression tests with:
```bash
python -m unittest discover -s tests
```

## Future Scope

- LLM integration for plain-English bug explanations and smarter fixes
- Support for additional languages (Java, C++, JavaScript)
- GitHub repository integration for pull-request-level analysis
