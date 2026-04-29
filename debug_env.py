# ============================================================
# debug_env.py  —  Run this to diagnose the API key issue
# python debug_env.py
# ============================================================
import os, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
print(f"Project root : {ROOT}")
print(f"Working dir  : {os.getcwd()}")

# Check .env file
env_path = ROOT / ".env"
print(f"\n.env path    : {env_path}")
print(f".env exists  : {env_path.exists()}")

if env_path.exists():
    print(f"\n.env contents (first 5 non-comment lines):")
    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            # Mask the actual key value for safety
            if "=" in stripped:
                k, _, v = stripped.partition("=")
                masked = v[:6] + "..." + v[-4:] if len(v) > 10 else v
                print(f"  {k} = {masked}")

# Check what os.environ has BEFORE importing config
print(f"\nBEFORE config import:")
for key in ["GROQ__API_KEY", "GROQ_API_KEY", "GROQ__MODEL_NAME"]:
    val = os.environ.get(key, "NOT FOUND")
    if val != "NOT FOUND" and len(val) > 10:
        val = val[:6] + "..." + val[-4:]
    print(f"  os.environ[{key!r}] = {val!r}")

# Now import config
sys.path.insert(0, str(ROOT))
from config import settings

print(f"\nAFTER config import:")
for key in ["GROQ__API_KEY", "GROQ_API_KEY", "GROQ__MODEL_NAME"]:
    val = os.environ.get(key, "NOT FOUND")
    if val != "NOT FOUND" and len(val) > 10:
        val = val[:6] + "..." + val[-4:]
    print(f"  os.environ[{key!r}] = {val!r}")

print(f"\nsettings.groq.api_key   = {repr(settings.groq.api_key[:6] + '...' if settings.groq.api_key else 'EMPTY')}")
print(f"settings.groq.model_name = {settings.groq.model_name!r}")

# Final verdict
key = settings.groq.api_key
if key and key.startswith("gsk_"):
    print(f"\n✅ API key loaded correctly ({len(key)} chars)")
else:
    print(f"\n❌ API key is empty or invalid: {repr(key[:20] if key else 'EMPTY')}")
    print("\nDIAGNOSTICS:")
    if not env_path.exists():
        print("  → .env file not found at expected location")
    else:
        raw = env_path.read_text(encoding="utf-8")
        if "GROQ__API_KEY" not in raw:
            print("  → GROQ__API_KEY not in .env file")
        elif 'GROQ__API_KEY=""' in raw or "GROQ__API_KEY=''" in raw:
            print("  → GROQ__API_KEY is set to empty string in .env")
        else:
            print("  → Key is in .env but not reaching the validator")
            print("  → Likely cause: pydantic-settings caching or import order issue")
            print("\n  SOLUTION: Change your .env to use single underscore:")
            print("    GROQ_API_KEY=gsk_your_key_here  (no quotes, no double underscore)")