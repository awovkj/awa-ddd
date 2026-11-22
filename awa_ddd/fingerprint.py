"""Concrete imported-code identity and reproducible installed core manifest."""
from __future__ import annotations

import hashlib
import json
import marshal
from pathlib import Path
import platform
import sys
import types


RUNTIME_RESOURCE_HASHES = {
    "resources/js_parser/manifest.json":
        "9cd41e076c3bcf2a4bc61bcfd52130d319b42354232d5d127c98ade42f614686",
    "resources/js_parser/parse-js.mjs":
        "972badd3720729ad0336ab6d610576d2b748a8f38e7ed9c3a9cea4ba1da28210",
    "resources/js_parser/vendor/acorn/LICENSE":
        "76a876cf886ff9be2a8b5e2e86514fed06223c8c9f0c1e9ee9606e93841e00b7",
    "resources/js_parser/vendor/acorn/package.json":
        "04d6fecaafb5e3d20a38fc3b64fed84bb3830a7759a8c00400ebcb87331fec00",
    "resources/js_parser/vendor/acorn/dist/acorn.mjs":
        "76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b",
}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def core_manifest(root=None):
    """Hash the package allowlist, independent of checkout/install location."""
    package = Path(root) if root is not None else Path(__file__).resolve().parent
    files = []
    for path in sorted(package.rglob("*.py")):
        relative = path.relative_to(package).as_posix()
        if path.name.startswith("tests_") or any(part.startswith(".") or part in {"__pycache__", "tests"}
                                                 for part in path.relative_to(package).parts):
            continue
        files.append({"path": "awa_ddd/" + relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    for relative, expected in RUNTIME_RESOURCE_HASHES.items():
        path = package / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("The installed JavaScript parser resource is missing or linked: " + relative)
        try:
            path.resolve(strict=True).relative_to(package.resolve(strict=True))
        except ValueError as exc:
            raise RuntimeError("The installed JavaScript parser resource escaped the package: " + relative) from exc
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError("The installed JavaScript parser resource changed: " + relative)
        files.append({"path": "awa_ddd/" + relative, "sha256": actual})
    files.sort(key=lambda row: row["path"])
    return {"schema": "awa-core-manifest/v1", "sha256": _digest(files), "files": files,
            "file_total": len(files)}


def loaded_identity():
    """Distinguish installed source bytes from objects actually imported here.

    Imported function bytecode is recorded separately because editing a source
    file after import does not change the running functions. No Git invocation
    or subprocess is needed in an installed wheel.
    """
    from . import __version__
    manifest = core_manifest()
    modules = []
    for name, module in sorted(list(sys.modules.items())):
        if name != "awa_ddd" and not name.startswith("awa_ddd."):
            continue
        origin = getattr(module, "__file__", None)
        if not origin:
            continue
        objects = []
        for key, value in sorted(vars(module).items()):
            if isinstance(value, types.FunctionType) and value.__module__ == name:
                objects.append([key, hashlib.sha256(marshal.dumps(value.__code__)).hexdigest()])
            elif isinstance(value, type) and value.__module__ == name:
                for member, function in sorted(vars(value).items()):
                    if isinstance(function, (classmethod, staticmethod)):
                        function = function.__func__
                    if isinstance(function, types.FunctionType):
                        objects.append([key + "." + member, hashlib.sha256(marshal.dumps(function.__code__)).hexdigest()])
        modules.append({"module": name, "origin": str(Path(origin).resolve()), "code_sha256": _digest(objects)})
    package_path = str(Path(__file__).resolve().parent)
    entry = sys.modules.get("awa_ddd.__main__") or sys.modules.get("__main__")
    entry_path = getattr(entry, "__file__", None)
    return {"schema": "awa-runtime-identity/v1", "engine_version": __version__,
            "package_path": package_path,
            "entrypoint_path": str(Path(entry_path).resolve()) if entry_path else None,
            "python_executable": sys.executable, "python_version": platform.python_version(),
            "core_manifest_sha256": manifest["sha256"], "core_file_total": manifest["file_total"],
            "loaded_code_sha256": _digest(modules), "loaded_module_total": len(modules),
            "source_identity": "installed_bytes", "loaded_identity": "imported_function_bytecode",
            "target_traffic_sent": False}
