import sys
from pathlib import Path

# Rendre le paquet importable sans installation (CI sur machine vierge)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
