"""Dependency expansion model. Does not load libraries or access the filesystem."""
from __future__ import annotations

import posixpath

from .macho import MachOError


def expand_dependency(path: str, loader: str, executable: str, rpaths: list[str]) -> list[str]:
    """Return lexical candidate paths; caller decides if an allowed bundle contains them."""
    def expand(value: str) -> str:
        for token, directory in (("@loader_path", posixpath.dirname(loader)),
                                 ("@executable_path", posixpath.dirname(executable))):
            if value == token or value.startswith(token + "/"):
                value = directory + value[len(token):]
                break
        if value.startswith("@"):
            raise MachOError(f"unsupported path token: {value}")
        if not posixpath.isabs(value):
            raise MachOError(f"dependency path must be absolute: {value}")
        return posixpath.normpath(value)

    if path.startswith("@rpath/"):
        return [expand(expand(rpath) + path[len("@rpath"):]) for rpath in rpaths]
    return [expand(path)]


def dependency_graph(image: dict, loader: str, executable: str) -> list[dict]:
    return [{**dep, "candidates": expand_dependency(dep["path"], loader, executable, image["rpaths"])}
            for dep in image["dependencies"] if dep["kind"] != "id"]
