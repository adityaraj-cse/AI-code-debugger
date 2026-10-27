"""
Code Analyzer - Mini Project
Detects bugs/code-smells in Python source files using AST,
categorizes them, and computes bug-distribution statistics
(function-wise, category-wise, severity-wise).
"""

import ast
import re
import sys
from collections import defaultdict


class Bug:
    def __init__(self, line, category, severity, message, fix, function="module-level"):
        self.line = line
        self.category = category      # Security / Logic / Style / Smell
        self.severity = severity      # Critical / High / Medium / Low
        self.message = message
        self.fix = fix
        self.function = function

    def to_dict(self):
        return {
            "line": self.line,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "fix": self.fix,
            "function": self.function,
        }


class CodeAnalyzer(ast.NodeVisitor):
    SQL_KEYWORD = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|REPLACE)\b", re.IGNORECASE)
    SECRET_NAME = re.compile(r"(?:PASSWORD|PASSWD|SECRET|API_KEY|ACCESS_KEY|TOKEN)", re.IGNORECASE)
    MUTABLE_DEFAULT_CALLS = {"dict", "list", "set"}
    SINGLETONS = (None, True, False, Ellipsis)

    def __init__(self, source_code, filename="code.py"):
        self.source = source_code
        self.filename = filename
        self.lines = source_code.splitlines()
        self.bugs = []
        self.function_ranges = {}   # func_name -> (start_line, end_line)
        self.function_loc = {}      # func_name -> lines of code
        self.current_function = "module-level"
        self.if_depth = 0
        self._reported_sql_lines = set()
        self.tree = ast.parse(source_code)

    # ---------- Helpers ----------
    def _add_bug(self, node, category, severity, message, fix):
        self.bugs.append(
            Bug(getattr(node, "lineno", 0), category, severity, message, fix, self.current_function)
        )

    def _add_sql_bug(self, node):
        line = getattr(node, "lineno", 0)
        if line in self._reported_sql_lines:
            return
        self._reported_sql_lines.add(line)
        self._add_bug(
            node, "Security", "Critical",
            "Possible SQL Injection via dynamically constructed SQL",
            "Use parameterized queries / prepared statements instead of string building"
        )

    def _contains_sql_keyword(self, node):
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if self.SQL_KEYWORD.search(child.value):
                    return True
        return False

    def _has_dynamic_value(self, node):
        return any(
            isinstance(child, (ast.Name, ast.Call, ast.Attribute, ast.Subscript, ast.JoinedStr))
            for child in ast.walk(node)
        )

    def _is_mutable_default(self, node):
        if isinstance(node, (ast.List, ast.Dict, ast.Set)):
            return True
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in self.MUTABLE_DEFAULT_CALLS
        )

    def _check_function(self, node):
        start, end = self._line_range(node)
        self.function_ranges[node.name] = (start, end)
        self.function_loc[node.name] = end - start + 1

        defaults = list(node.args.defaults) + [
            default for default in node.args.kw_defaults if default is not None
        ]
        for default in defaults:
            if self._is_mutable_default(default):
                self._add_bug(
                    default, "Logic", "High",
                    f"Function '{node.name}' uses a mutable default argument",
                    "Use None as default and initialize inside the function body"
                )

        if (end - start) > 25:
            self._add_bug(
                node, "Smell", "Medium",
                f"Function '{node.name}' is too long ({end - start} lines)",
                "Break the function into smaller, single-responsibility functions"
            )

    def _line_range(self, node):
        start = node.lineno
        end = max(
            [getattr(n, "lineno", start) for n in ast.walk(node)] + [start]
        )
        return start, end

    # ---------- Visitors ----------
    def visit_FunctionDef(self, node):
        self._check_function(node)
        prev = self.current_function
        self.current_function = node.name
        previous_depth = self.if_depth
        self.if_depth = 0
        self.generic_visit(node)
        self.if_depth = previous_depth
        self.current_function = prev

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Try(self, node):
        for handler in node.handlers:
            if handler.type is None:
                message = "Bare 'except:' clause catches all exceptions"
                if any(isinstance(statement, ast.Pass) for statement in handler.body):
                    message += " and silently ignores them"
                self._add_bug(
                    handler, "Logic", "High",
                    message,
                    "Catch specific exceptions, e.g. 'except ValueError:'"
                )
            elif (
                isinstance(handler.type, ast.Name)
                and handler.type.id in {"Exception", "BaseException"}
            ):
                self._add_bug(
                    handler, "Logic", "Medium",
                    f"Broad exception handler catches '{handler.type.id}'",
                    "Catch only the exception types this code can handle"
                )
        self.generic_visit(node)

    def visit_Compare(self, node):
        values = [node.left] + list(node.comparators)
        for op, left, right in zip(node.ops, values, values[1:]):
            if isinstance(op, (ast.Eq, ast.NotEq)) and any(
                isinstance(value, ast.Constant) and value.value is None
                for value in (left, right)
            ):
                self._add_bug(
                    node, "Style", "Low",
                    "Comparison to None using '==' or '!='",
                    "Use 'is None' / 'is not None' instead"
                )
                break
            if isinstance(op, (ast.Is, ast.IsNot)) and any(
                isinstance(value, ast.Constant) and value.value not in self.SINGLETONS
                for value in (left, right)
            ):
                self._add_bug(
                    node, "Style", "Low",
                    "Identity comparison used with a non-singleton value",
                    "Use '==' / '!=' for value comparisons; reserve 'is' for None and singletons"
                )
                break
        self.generic_visit(node)

    def visit_If(self, node):
        parent_depth = self.if_depth
        depth = parent_depth + 1
        if depth == 3:
            self._add_bug(
                node, "Smell", "Medium",
                f"Deeply nested if-block (depth {depth})",
                "Use early returns / guard clauses to reduce nesting"
            )
        self.visit(node.test)
        for statement in node.body:
            self.if_depth = depth
            self.visit(statement)
        for statement in node.orelse:
            is_elif = (
                isinstance(statement, ast.If)
                and getattr(statement, "lineno", 0) > 0
                and self.lines[statement.lineno - 1].lstrip().startswith("elif")
            )
            self.if_depth = parent_depth if is_elif else depth
            self.visit(statement)
        self.if_depth = parent_depth

    def visit_BinOp(self, node):
        if (
            isinstance(node.op, (ast.Add, ast.Mod))
            and self._contains_sql_keyword(node)
            and self._has_dynamic_value(node)
        ):
            self._add_sql_bug(node)

        # Detect definite division or modulo by a literal zero.
        if (
            isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod))
            and isinstance(node.right, ast.Constant)
            and isinstance(node.right.value, (int, float))
            and not isinstance(node.right.value, bool)
            and node.right.value == 0
        ):
            self._add_bug(
                node, "Logic", "High",
                "Division or modulo by zero will raise ZeroDivisionError",
                "Check that the denominator is not zero before this operation"
            )

        self.generic_visit(node)
    def visit_Assign(self, node):
        for target in node.targets:
            self._check_secret_assignment(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is not None:
            self._check_secret_assignment(node.target, node.value)
        self.generic_visit(node)

    def _check_secret_assignment(self, target, value):
        if (
            isinstance(target, ast.Name)
            and self.SECRET_NAME.search(target.id)
            and isinstance(value, ast.Constant)
            and isinstance(value.value, str)
            and value.value
        ):
            self._add_bug(
                value, "Security", "Critical",
                f"Hardcoded credential detected in variable '{target.id}'",
                "Move secrets to environment variables or a secure vault"
            )

    def visit_JoinedStr(self, node):
        if self._contains_sql_keyword(node) and any(
            not isinstance(value, ast.Constant) for value in node.values
        ):
            self._add_sql_bug(node)
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            self._add_bug(
                node, "Security", "High",
                f"Use of potentially unsafe '{node.func.id}()'",
                "Avoid evaluating dynamic code; use a safe parser or explicit logic"
            )

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and node.args
            and self._contains_sql_keyword(node.func.value)
        ):
            self._add_sql_bug(node)

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"run", "call", "Popen"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )
        ):
            self._add_bug(
                node, "Security", "High",
                "Subprocess is run with shell=True",
                "Pass an argument list and keep shell=False; validate untrusted input"
            )

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"load", "loads"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
        ):
            self._add_bug(
                node, "Security", "High",
                "Pickle can execute arbitrary code when loading untrusted data",
                "Use a safe serialization format such as JSON for untrusted data"
            )

        self.generic_visit(node)

    def visit_Module(self, node):
        self.generic_visit(node)

    # ---------- Unused variable / import detection ----------
    def find_unused_names(self):
        class Collector(ast.NodeVisitor):
            def __init__(self, outer):
                self.outer = outer
                self.scopes = [{
                    "kind": "module",
                    "function": "module-level",
                    "parent": None,
                    "bindings": {},
                    "used": set(),
                    "used_bindings": set(),
                    "reportable": set(),
                    "globals": set(),
                    "nonlocals": set(),
                }]
                self.all_scopes = list(self.scopes)

            @property
            def scope(self):
                return self.scopes[-1]

            def _push_scope(self, kind, function):
                scope = {
                    "kind": kind,
                    "function": function,
                    "parent": self.scope,
                    "bindings": {},
                    "used": set(),
                    "used_bindings": set(),
                    "reportable": set(),
                    "globals": set(),
                    "nonlocals": set(),
                }
                self.scopes.append(scope)
                self.all_scopes.append(scope)

            def _bind(self, name, lineno, reportable=True):
                target_scope = self.scope
                if name in self.scope["globals"]:
                    target_scope = self.all_scopes[0]
                elif name in self.scope["nonlocals"]:
                    parent = self.scope["parent"]
                    while parent is not None and parent["kind"] != "module":
                        if parent["kind"] == "function" and name in parent["bindings"]:
                            target_scope = parent
                            break
                        parent = parent["parent"]
                    if parent is None or parent["kind"] == "module":
                        target_scope = self.scope
                target_scope["bindings"].setdefault(name, lineno)
                if reportable and target_scope is self.scope:
                    target_scope["reportable"].add(name)

            def _visit_outer_expressions(self, node):
                for decorator in node.decorator_list:
                    self.visit(decorator)
                for default in node.args.defaults:
                    self.visit(default)
                for default in node.args.kw_defaults:
                    if default is not None:
                        self.visit(default)
                for argument in (
                    node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                ):
                    if argument.annotation:
                        self.visit(argument.annotation)
                if node.args.vararg and node.args.vararg.annotation:
                    self.visit(node.args.vararg.annotation)
                if node.args.kwarg and node.args.kwarg.annotation:
                    self.visit(node.args.kwarg.annotation)
                if node.returns:
                    self.visit(node.returns)

            def _visit_function(self, node):
                self._bind(node.name, node.lineno, reportable=False)
                self._visit_outer_expressions(node)
                self._push_scope("function", node.name)
                args = (
                    node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                )
                if node.args.vararg:
                    args.append(node.args.vararg)
                if node.args.kwarg:
                    args.append(node.args.kwarg)
                for argument in args:
                    self._bind(argument.arg, argument.lineno, reportable=False)
                for statement in node.body:
                    self.visit(statement)
                self.scopes.pop()

            def visit_FunctionDef(self, node):
                self._visit_function(node)

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_ClassDef(self, node):
                self._bind(node.name, node.lineno, reportable=False)
                for expression in node.decorator_list + node.bases:
                    self.visit(expression)
                for keyword in node.keywords:
                    self.visit(keyword.value)
                self._push_scope("class", node.name)
                for statement in node.body:
                    self.visit(statement)
                self.scopes.pop()

            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Store):
                    self._bind(node.id, node.lineno)
                elif isinstance(node.ctx, ast.Load):
                    self.scope["used"].add(node.id)

            def visit_AugAssign(self, node):
                if isinstance(node.target, ast.Name):
                    self.scope["used"].add(node.target.id)
                else:
                    self.visit(node.target)
                self.visit(node.value)

            def visit_Import(self, node):
                for alias in node.names:
                    name = alias.asname or alias.name.split(".")[0]
                    self._bind(name, node.lineno)

            def visit_ImportFrom(self, node):
                for alias in node.names:
                    if alias.name != "*":
                        self._bind(alias.asname or alias.name, node.lineno)

            def visit_Global(self, node):
                self.scope["globals"].update(node.names)

            def visit_Nonlocal(self, node):
                self.scope["nonlocals"].update(node.names)

        collector = Collector(self)
        collector.visit(self.tree)

        for scope in collector.all_scopes:
            for name in scope["used"]:
                target_scope = scope
                if name in scope["globals"]:
                    target_scope = collector.all_scopes[0]
                elif name in scope["nonlocals"]:
                    target_scope = scope["parent"]
                    while target_scope is not None:
                        if target_scope["kind"] == "function" and name in target_scope["bindings"]:
                            break
                        target_scope = target_scope["parent"]
                else:
                    while target_scope is not None and name not in target_scope["bindings"]:
                        target_scope = target_scope["parent"]
                        if (
                            target_scope is not None
                            and target_scope["kind"] == "class"
                            and scope["kind"] == "function"
                        ):
                            target_scope = target_scope["parent"]
                if target_scope is not None:
                    target_scope["used_bindings"].add(name)

        for scope in collector.all_scopes:
            for name in scope["reportable"]:
                if name.startswith("_"):
                    continue
                if name not in scope["used_bindings"]:
                    lineno = scope["bindings"][name]
                    self.bugs.append(Bug(
                        lineno, "Style", "Low",
                        f"Unused variable/import: '{name}'",
                        "Remove it if not needed",
                        scope["function"]
                    ))

    # ---------- Run everything ----------
    def analyze(self):
        self.visit(self.tree)
        self.find_unused_names()
        return self.bugs


# ---------------- Reporting / Statistics ----------------

def build_report(bugs, function_loc):
    total = len(bugs)
    by_function = defaultdict(int)
    by_category = defaultdict(int)
    by_severity = defaultdict(int)

    for b in bugs:
        by_function[b.function] += 1
        by_category[b.category] += 1
        by_severity[b.severity] += 1

    def pct(d):
        return {k: round((v / total) * 100, 1) if total else 0 for k, v in d.items()}

    # density = bugs / LOC for each function (fallback LOC=1 for module-level)
    density = {}
    for func, count in by_function.items():
        loc = function_loc.get(func, 10)
        density[func] = round((count / loc) * 100, 1)

    severity_weight = {"Critical": 10, "High": 6, "Medium": 3, "Low": 1}
    penalty = sum(severity_weight.get(b.severity, 1) for b in bugs)
    health_score = max(0, 100 - penalty)

    return {
        "total_bugs": total,
        "by_function_count": dict(by_function),
        "by_function_pct": pct(by_function),
        "by_function_density_pct": density,
        "by_category_count": dict(by_category),
        "by_category_pct": pct(by_category),
        "by_severity_count": dict(by_severity),
        "by_severity_pct": pct(by_severity),
        "health_score": health_score,
        "bugs": [b.to_dict() for b in bugs],
    }


def analyze_source(source_code, filename="code.py"):
    """Analyze Python source and report syntax errors as findings."""
    try:
        analyzer = CodeAnalyzer(source_code, filename=filename)
    except SyntaxError as error:
        syntax_bug = Bug(
            error.lineno or 1,
            "Syntax",
            "High",
            f"Python syntax error: {error.msg}",
            "Fix the indicated syntax, such as a missing colon, bracket, quote, or valid indentation"
        )
        return build_report([syntax_bug], {})

    bugs = analyzer.analyze()
    return build_report(bugs, analyzer.function_loc)
def analyze_file(path):
    with open(path, "r") as f:
        source = f.read()
    return analyze_source(source, filename=path)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "sample_buggy_code.py"
    report = analyze_file(target)
    print(f"\n=== Code Analysis Report: {target} ===")
    print(f"Total bugs found: {report['total_bugs']}")
    print(f"Health Score: {report['health_score']}/100\n")

    print("-- By Severity --")
    for k, v in report["by_severity_count"].items():
        print(f"  {k}: {v} ({report['by_severity_pct'][k]}%)")

    print("\n-- By Category --")
    for k, v in report["by_category_count"].items():
        print(f"  {k}: {v} ({report['by_category_pct'][k]}%)")

    print("\n-- By Function (bug share) --")
    for k, v in report["by_function_count"].items():
        print(f"  {k}: {v} bugs ({report['by_function_pct'][k]}% of total, "
              f"density {report['by_function_density_pct'][k]}%)")

    print("\n-- Detailed Bug List --")
    for b in report["bugs"]:
        print(f"  Line {b['line']:>3} [{b['severity']:<8}] ({b['category']}) "
              f"in {b['function']}: {b['message']}")
        print(f"        Fix: {b['fix']}")
