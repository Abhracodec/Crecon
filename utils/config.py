import json
from pathlib import Path

CONFIG_DIR  = Path.home() / ".crecon"
CONFIG_FILE = CONFIG_DIR / "config.json"

PROVIDERS = ("anthropic", "openai", "groq", "gemini", "github")


def _load():
    if not CONFIG_FILE.exists():
        return {"keys": []}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {"keys": []}


def _save(data):
    CONFIG_DIR.mkdir(exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2))
    CONFIG_FILE.chmod(0o600)


def add_key(api_key, provider="anthropic"):
    provider = provider.lower()
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider. Choose from: {', '.join(PROVIDERS)}")
    data = _load()
    for k in data["keys"]:
        if k["key"] == api_key:
            print(f"  Key already exists.")
            return
    data["keys"].append({"key": api_key, "provider": provider, "active": True})
    _save(data)
    print(f"  Key added ({provider}).")


def remove_key(index):
    data = _load()
    keys = data["keys"]
    if index < 1 or index > len(keys):
        print(f"  Invalid index. You have {len(keys)} key(s).")
        return
    removed = keys.pop(index - 1)
    _save(data)
    print(f"  Removed key #{index} ({removed['provider']})")


def list_keys():
    data = _load()
    keys = data["keys"]
    if not keys:
        print("  No keys saved. Run: crecon config --add-key <key>")
        return
    print()
    for i, k in enumerate(keys, 1):
        masked   = k["key"][:8] + "..." + k["key"][-4:]
        provider = k["provider"]
        status   = "active" if k.get("active", True) else "exhausted"
        print(f"  {i}.  {provider:<12}  {masked}  [{status}]")
    print()


def get_keys(provider=None):
    data = _load()
    keys = [k for k in data["keys"] if k.get("active", True)]
    if provider:
        keys = [k for k in keys if k["provider"] == provider]
    return keys


def mark_exhausted(api_key):
    data = _load()
    for k in data["keys"]:
        if k["key"] == api_key:
            k["active"] = False
    _save(data)


def has_keys():
    return len(get_keys()) > 0