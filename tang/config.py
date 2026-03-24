import os
from pathlib import Path

JWK_PATH = Path(os.getenv("TANG_JWK_PATH", default="keys"))
