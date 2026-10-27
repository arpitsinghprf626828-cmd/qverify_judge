import os, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT); sys.path.insert(0, str(ROOT))
if not Path("samples/batch/ground_truth.json").exists(): subprocess.run([sys.executable, "generate_samples.py"], check=True)
