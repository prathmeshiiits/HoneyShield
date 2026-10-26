import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class StaticIntegrityTests(unittest.TestCase):
    def test_required_project_files_exist_and_are_nonempty(self):
        required = [
            "app.py", "risk_engine.py", "requirements.txt", "README.md", "run.ps1", "run.bat", "test.ps1",
            "templates/base.html", "templates/login.html", "templates/user_dashboard.html",
            "templates/decoy_dashboard.html", "templates/admin_dashboard.html",
            "static/css/style.css", "static/js/app.js", "tests/test_app.py", "tests/test_risk_engine.py",
            "docs/architecture.md", ".gitignore",
        ]
        for relative in required:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            self.assertGreater(path.stat().st_size, 0, relative)

    def test_python_sources_parse(self):
        for path in [ROOT / "app.py", ROOT / "risk_engine.py", *sorted((ROOT / "tests").glob("*.py"))]:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_template_endpoint_references_exist(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        module = ast.parse(source)
        function_names = {node.name for node in ast.walk(module) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        endpoint_names = set(function_names) | {"static"}
        referenced = set()
        for template in (ROOT / "templates").glob("*.html"):
            referenced.update(re.findall(r"url_for\(['\"]([^'\"]+)['\"]", template.read_text(encoding="utf-8")))
        self.assertTrue(referenced)
        self.assertEqual(referenced - endpoint_names, set(), f"Unimplemented template endpoints: {referenced - endpoint_names}")

    def test_jinja_templates_parse(self):
        try:
            from jinja2 import Environment
        except ImportError:
            self.skipTest("Jinja2 is installed as a Flask dependency; unavailable in this validation environment")
        environment = Environment()
        for template in (ROOT / "templates").glob("*.html"):
            environment.parse(template.read_text(encoding="utf-8"))

    def test_drawer_modal_and_anchor_destinations_are_present(self):
        base = (ROOT / "templates/base.html").read_text(encoding="utf-8")
        admin = (ROOT / "templates/admin_dashboard.html").read_text(encoding="utf-8")
        script = (ROOT / "static/js/app.js").read_text(encoding="utf-8")
        for required in ["id=\"menuToggle\"", "id=\"navDrawer\"", "id=\"drawerBackdrop\"", "id=\"demoDisclosure\"", "id=\"demoDisclosureContinue\""]:
            self.assertIn(required, base)
        for anchor in ["scenario-console", "event-stream", "methodology"]:
            self.assertIn(f'id=\"{anchor}\"', admin)
            self.assertIn(f"#{anchor}", base)
        for interaction in ["openDrawer", "closeDrawer", "sessionStorage", "Escape"]:
            self.assertIn(interaction, script)

    def test_no_runtime_cdn_or_external_font_dependency(self):
        sources = "\n".join(path.read_text(encoding="utf-8") for path in [*(ROOT / "templates").glob("*.html"), ROOT / "static/css/style.css", ROOT / "static/js/app.js"])
        self.assertNotRegex(sources.lower(), r"https?://(?:cdn\.|fonts\.googleapis\.com|fonts\.gstatic\.com)")

    def test_event_recorder_call_matches_helper_signature(self):
        module = ast.parse((ROOT / "app.py").read_text(encoding="utf-8"))
        helpers = [node for node in ast.walk(module) if isinstance(node, ast.FunctionDef) and node.name == "append_event_raw"]
        self.assertEqual(len(helpers), 1)
        helper = helpers[0]
        required_positional = len(helper.args.args) - len(helper.args.defaults)
        calls = [node for node in ast.walk(module) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "append_event_raw"]
        self.assertGreaterEqual(len(calls), 2)
        for call in calls:
            self.assertEqual(len(call.args), required_positional, "append_event_raw call has wrong positional argument count")

    def test_app_exposes_required_route_decorators(self):
        source = (ROOT / "app.py").read_text(encoding="utf-8")
        for route in ["/login", "/dashboard", "/decoy", "/admin", "/admin/simulate/<scenario>", "/admin/reset", "/healthz"]:
            self.assertIn(route, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
