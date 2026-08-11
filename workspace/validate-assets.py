from pathlib import Path
import re

root = Path(r"D:\notion\gateway\web")
html = (root / "index.html").read_text(encoding="utf-8")
js = (root / "app.js").read_text(encoding="utf-8")
css = (root / "app.css").read_text(encoding="utf-8")
ids = set(re.findall(r'\bid="([A-Za-z0-9_-]+)"', html))
refs = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', js))
missing = sorted(refs - ids)
if missing:
    raise SystemExit("JS references missing HTML IDs: " + ", ".join(missing))
if len(ids) != len(re.findall(r'\bid="([A-Za-z0-9_-]+)"', html)):
    raise SystemExit("Duplicate HTML IDs detected")
for forbidden in ("激活码", "license", "auth_token", "connToken", "toggleTokenBtn", "Bearer 整串", "X-Console-Token", "gwToken", "?t="):
    if forbidden.lower() in (html + js).lower():
        raise SystemExit(f"Forbidden activation/static-token UI text: {forbidden}")
if "--canvas: #ffffff" not in css.lower():
    raise SystemExit("White canvas palette missing")
if "@media (max-width: 430px)" not in css:
    raise SystemExit("Mobile breakpoint missing")
print(f"Asset validation passed: {len(ids)} IDs, {len(refs)} JS references")
