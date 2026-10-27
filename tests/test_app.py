from pathlib import Path
from streamlit.testing.v1 import AppTest
APP = str(Path(__file__).resolve().parent.parent / "app.py")
def start(role):
    at = AppTest.from_file(APP, default_timeout=180); at.session_state["user"] = {"name": role + "1", "role": role}; return at.run()
def test_login_screen():
    at = AppTest.from_file(APP, default_timeout=60).run(); assert not at.exception
def test_admin_full_flow():
    at = start("admin"); assert not at.exception
    at.radio[0].set_value("Problem sample").run(); [b for b in at.button if b.label == "▶ Run validation"][0].click().run()
    assert not at.exception and len(at.session_state["result"]["findings"]) > 10
    [b for b in at.button if "Generate & sign" in b.label][0].click().run(); assert not at.exception and at.session_state["env"]
def test_applicant_cannot_see_admin_tabs():
    at = start("applicant"); labels = [t.label for t in at.tabs]; assert "⚙️ Rules" not in labels and "🧾 Audit" not in labels
