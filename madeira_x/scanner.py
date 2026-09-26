"""Conservative hints derived from imported libraries. No launch guarantee."""
from __future__ import annotations

from .macho import inspect_path


def scan(path):
    report = inspect_path(path)
    for item in report["slices"]:
        deps = [d["path"] for d in item["dependencies"] if d["kind"] != "id"]
        checks = {name: any(name.lower() in dep.lower() for dep in deps) for name in
                  ("AppKit", "Foundation", "Metal", "OpenGL", "CoreAudio", "GameController", "SDL2", "SDL3", "Swift")}
        item["detected_dependencies"] = checks
        item["assessment"] = ("candidate for further inspection" if item["architecture"] == "arm64" and item["platform"] == "macOS"
                              else "outside initial ARM64 macOS target")
        item["execution_verified"] = False
        item["notes"] = ["Dependency presence does not establish API compatibility or executable code permission."]
    return report
