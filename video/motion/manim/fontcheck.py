import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import brand  # noqa: E402,F401
import manimpango  # noqa: E402

print(sorted(f for f in manimpango.list_fonts() if "Inter" in f or "JetBrains" in f))
