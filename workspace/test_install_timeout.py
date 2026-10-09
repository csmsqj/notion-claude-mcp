import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime-patches'))
from command_timeout_overlay import is_dependency_install
class InstallTimeoutTests(unittest.TestCase):
 def test_install_commands(self):
  for c in ['npm ci','npm.cmd install --no-audit','pip install pytest','pip3.exe install foo',r'.\python\.venv\Scripts\python.exe -m pip install -r python\requirements.lock','python -m pip install deepagents','uv pip install pytest','uv sync']:
   with self.subTest(command=c):self.assertTrue(is_dependency_install(c),c)
 def test_non_install(self):
  for c in ['npm test','python -m pytest','pip list','echo pip install','python -m pip list','npm run build']:
   with self.subTest(command=c):self.assertFalse(is_dependency_install(c),c)
