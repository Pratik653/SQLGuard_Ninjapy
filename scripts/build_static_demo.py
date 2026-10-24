"""Build the static (browser-only) playground into a directory ready for any static host.

    python scripts/build_static_demo.py site/

The site runs SQLGuard Ninja in the visitor's browser with Pyodide. Validation and the
synthetic SQLite database live in a Web Worker; no server, no API key, no shared database.

Everything is self-hosted under the output directory, so the page loads no third-party code:

* Pyodide core, pinned by the SHA-256 that GitHub publishes for the release asset;
* Pyodide packages (pydantic, PyYAML, sqlite3 and their dependencies), each verified against
  the SHA-256 in the release's ``pyodide-lock.json``;
* the sqlglot wheel from PyPI (``pip download``, verified against PyPI's published digest);
* a freshly built SQLGuard Ninja wheel from this checkout.

Downloads are cached in ``.cache/static-demo``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "sqlguard_ninja" / "demo" / "static"
CACHE = ROOT / ".cache" / "static-demo"
PYODIDE_VERSION = "0.29.5"
PYODIDE_CORE = (
    f"https://github.com/pyodide/pyodide/releases/download/{PYODIDE_VERSION}/"
    f"pyodide-core-{PYODIDE_VERSION}.tar.bz2"
)
PYODIDE_CORE_SHA256 = "ab08aafc11a3c9a0fe73825eb2cec78bda9464348dd17414e7ec0132ef3451e8"
PYODIDE_CDN = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/"
CORE_FILES = (
    "pyodide.js",
    "pyodide.asm.js",
    "pyodide.asm.wasm",
    "python_stdlib.zip",
    "pyodide-lock.json",
)
PACKAGES = ("pydantic", "pyyaml", "sqlite3")
CSP = (
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; "
    "img-src 'self' data:; connect-src 'self'; worker-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'none'; object-src 'none'"
)
NOTICE = """Third-party components bundled in this static site
=====================================================

Pyodide {pyodide} (MPL-2.0) https://github.com/pyodide/pyodide, including CPython (PSF License)
and SQLite (public domain).
sqlglot {sqlglot} (MIT) https://github.com/tobymao/sqlglot
pydantic and pydantic-core (MIT), PyYAML (MIT), typing-extensions (PSF-2.0),
annotated-types (MIT), typing-inspection (MIT), as packaged by Pyodide.
SQLGuard Ninja (Apache-2.0) https://github.com/Pratik653/SQLGuard_Ninjapy

All data shown by this site is synthetic.
"""


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, expected: str) -> Path:
    if not (dest.exists() and sha256(dest) == expected):
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        with urllib.request.urlopen(url, timeout=120) as r, tmp.open("wb") as fh:  # noqa: S310
            shutil.copyfileobj(r, fh)
        tmp.replace(dest)
    actual = sha256(dest)
    if actual != expected:
        dest.unlink()
        raise SystemExit(f"checksum mismatch for {url}: {actual} != {expected}")
    return dest


def pyodide_core(out: Path) -> dict:
    archive = fetch(PYODIDE_CORE, CACHE / Path(PYODIDE_CORE).name, PYODIDE_CORE_SHA256)
    with tarfile.open(archive, "r:bz2") as tar:
        for name in CORE_FILES:
            member = tar.getmember(f"pyodide/{name}")
            src = tar.extractfile(member)
            assert src is not None
            (out / name).write_bytes(src.read())
    return json.loads((out / "pyodide-lock.json").read_text(encoding="utf-8"))


def pyodide_packages(lock: dict, out: Path) -> list[str]:
    pkgs = lock["packages"]
    needed: list[str] = []

    def add(name: str) -> None:
        name = name.lower().replace("_", "-")
        if name in needed:
            return
        needed.append(name)
        for dep in pkgs[name].get("depends", []):
            add(dep)

    for name in PACKAGES:
        add(name)
    for name in needed:
        info = pkgs[name]
        path = fetch(
            PYODIDE_CDN + info["file_name"], CACHE / "pkgs" / info["file_name"], info["sha256"]
        )
        shutil.copy2(path, out / info["file_name"])
    return needed


def sqlglot_wheel(dest: Path) -> Path:
    ver = version("sqlglot")
    meta = json.loads(
        urllib.request.urlopen(f"https://pypi.org/pypi/sqlglot/{ver}/json", timeout=60).read()
    )
    wheel = next(u for u in meta["urls"] if u["filename"].endswith("-py3-none-any.whl"))
    return fetch(wheel["url"], dest / wheel["filename"], wheel["digests"]["sha256"])


def own_wheel(dest: Path) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", tmp, str(ROOT)],
            check=True,
            capture_output=True,
        )
        built = next(Path(tmp).glob("sqlguard_ninja-*.whl"))
        return Path(shutil.copy2(built, dest / built.name))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out", type=Path)
    args = ap.parse_args()
    out: Path = args.out.resolve()
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(STATIC, out)
    (out / "pyodide").mkdir()
    (out / "wheels").mkdir()
    lock = pyodide_core(out / "pyodide")
    packages = pyodide_packages(lock, out / "pyodide")
    wheels = [sqlglot_wheel(CACHE / "wheels"), own_wheel(out / "wheels")]
    shutil.copy2(wheels[0], out / "wheels" / wheels[0].name)
    config = {
        "mode": "pyodide",
        "pyodide": "pyodide/",
        "packages": list(PACKAGES),
        "wheels": [f"wheels/{w.name}" for w in wheels],
    }
    (out / "config.json").write_text(json.dumps(config, indent=1) + "\n", encoding="utf-8")
    (out / "NOTICE.txt").write_text(
        NOTICE.format(pyodide=PYODIDE_VERSION, sqlglot=version("sqlglot")), encoding="utf-8"
    )
    (out / ".nojekyll").write_text("", encoding="utf-8")
    # Header rules for hosts that read them (Netlify, Cloudflare Pages); ignored elsewhere.
    (out / "_headers").write_text(
        "/*\n"
        f"  Content-Security-Policy: {CSP}\n"
        "  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n"
        "  X-Frame-Options: DENY\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n",
        encoding="utf-8",
    )
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    print(f"built {out} ({size / 1e6:.1f} MB); pyodide packages: {', '.join(packages)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
