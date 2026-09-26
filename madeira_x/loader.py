"""Host-side validation and virtual image model; does not map executable memory."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from .macho import MAX_INPUT, MachOError, _require, inspect


@dataclass(frozen=True)
class VirtualAddressSpace:
    segments: tuple[dict, ...]

    def __post_init__(self):
        ordered = sorted((s for s in self.segments if s["vmsize"]), key=lambda s: s["vmaddr"])
        for left, right in zip(ordered, ordered[1:]):
            _require(left["vmaddr"] + left["vmsize"] <= right["vmaddr"], "overlapping VM segments")
        backed = sorted((s for s in self.segments if s["filesize"]), key=lambda s: s["fileoff"])
        for left, right in zip(backed, backed[1:]):
            _require(left["fileoff"] + left["filesize"] <= right["fileoff"], "overlapping file-backed segments")

    def segment_for_vm(self, address: int) -> dict | None:
        return next((s for s in self.segments if s["vmaddr"] <= address < s["vmaddr"] + s["vmsize"]), None)

    def vm_to_file(self, address: int) -> int | None:
        segment = self.segment_for_vm(address)
        if segment and address - segment["vmaddr"] < segment["filesize"]:
            return segment["fileoff"] + address - segment["vmaddr"]
        return None

    def file_to_vm(self, offset: int) -> int | None:
        for s in self.segments:
            if s["filesize"] and s["fileoff"] <= offset < s["fileoff"] + s["filesize"]:
                return s["vmaddr"] + offset - s["fileoff"]
        return None


def _uleb(data: bytes, start: int) -> tuple[int, int]:
    value = 0
    for i in range(10):
        _require(start + i < len(data), "truncated ULEB128")
        byte = data[start + i]
        value |= (byte & 127) << (7 * i)
        _require(value < 1 << 64, "ULEB128 overflow")
        if not byte & 128:
            return value, start + i + 1
    raise MachOError("ULEB128 too long")


def parse_exports(blob: bytes) -> list[dict]:
    if not blob:
        return []
    exports = []
    visited = set()

    def walk(offset: int, prefix: str, depth: int):
        _require(depth < 128 and offset < len(blob) and offset not in visited, "invalid or cyclic export trie")
        visited.add(offset)
        terminal_size, pos = _uleb(blob, offset)
        _require(terminal_size <= len(blob) - pos, "truncated export terminal")
        end = pos + terminal_size
        if terminal_size:
            flags, at = _uleb(blob, pos)
            if flags & 0x08:  # reexport: ordinal and imported name
                ordinal, at = _uleb(blob, at)
                _require(at < end and b"\0" in blob[at:end], "invalid reexport name")
                name = blob[at:end].split(b"\0", 1)[0].decode("utf-8", "replace")
                exports.append({"name": prefix, "flags": flags, "reexport_ordinal": ordinal, "imported_name": name})
            else:
                value, at = _uleb(blob, at)
                exports.append({"name": prefix, "flags": flags, "value": value})
            _require(at <= end, "export terminal exceeds declared size")
        _require(end < len(blob), "missing export child count")
        count = blob[end]
        at = end + 1
        for _ in range(count):
            stop = blob.find(b"\0", at)
            _require(stop >= 0 and stop - at <= 1024, "invalid export edge")
            edge = blob[at:stop].decode("utf-8", "replace")
            _require(bool(edge), "empty export edge")
            child, at = _uleb(blob, stop + 1)
            walk(child, prefix + edge, depth + 1)
        visited.remove(offset)

    walk(0, "", 0)
    return exports


def _chained_metadata(blob: bytes) -> dict:
    _require(len(blob) >= 28, "truncated chained fixups header")
    version, starts, imports, symbols, count, fmt, symbol_fmt = struct.unpack_from("<7I", blob)
    _require(version == 0 and symbol_fmt == 0, "unsupported chained fixups header version/format")
    _require(starts < len(blob) and imports <= len(blob) and symbols <= len(blob), "invalid chained fixups offsets")
    _require(fmt in (1, 2, 3), f"unsupported chained imports format {fmt}")
    entry_size = {1: 4, 2: 8, 3: 16}[fmt]
    _require(count <= (len(blob) - imports) // entry_size, "chained imports outside payload")
    _require(starts + 4 <= len(blob), "truncated chained starts")
    segment_count = struct.unpack_from("<I", blob, starts)[0]
    _require(segment_count <= (len(blob) - starts - 4) // 4, "truncated chained segment starts")
    pointer_formats = []
    for i in range(segment_count):
        rel = struct.unpack_from("<I", blob, starts + 4 + i * 4)[0]
        if not rel:
            pointer_formats.append(None)
            continue
        at = starts + rel
        _require(at >= starts + 4 + segment_count * 4 and at + 22 <= len(blob), "truncated chained segment info")
        segment_size, page_size, pointer_format = struct.unpack_from("<IHH", blob, at)
        page_count = struct.unpack_from("<H", blob, at + 20)[0]
        _require(segment_size >= 22 + 2 * page_count and segment_size <= len(blob) - at, "invalid chained page table")
        _require(page_size in (0x1000, 0x4000), "unsupported chained page size")
        pointer_formats.append(pointer_format)
    imports_table = []
    for i in range(count):
        at = imports + i * entry_size
        word = struct.unpack_from("<Q" if fmt == 3 else "<I", blob, at)[0]
        if fmt == 3:
            ordinal = word & 0xFFFF
            weak = bool(word & (1 << 16))
            name_offset = word >> 32
            addend = struct.unpack_from("<q", blob, at + 8)[0]
        else:
            ordinal = word & 255
            weak = bool(word & 256)
            name_offset = word >> 9
            addend = struct.unpack_from("<i", blob, at + 4)[0] if fmt == 2 else 0
        name_at = symbols + name_offset
        _require(name_at < len(blob), "chained import name outside payload")
        end = blob.find(b"\0", name_at)
        _require(end >= 0, "unterminated chained import name")
        imports_table.append({"name": blob[name_at:end].decode("utf-8", "replace"), "ordinal": ordinal,
                              "weak": weak, "addend": addend, "resolved": False})
    # Pointer chains are deliberately not decoded or applied at this stage.
    return {"version": version, "import_count": count, "imports_format": fmt,
            "segment_count": segment_count, "pointer_formats": pointer_formats,
            "imports": imports_table, "pointer_chains_decoded": False}


def prepare_image(data: bytes) -> dict:
    """Construct a validated, non-executable image plan from a thin or universal binary."""
    _require(len(data) <= MAX_INPUT, "file exceeds inspection limit")
    slices = inspect(data)["slices"]
    candidates = [s for s in slices if s["architecture"] == "arm64" and s["platform"] == "macOS"]
    _require(len(candidates) == 1, "expected exactly one ARM64 macOS slice")
    image = candidates[0]
    base = image.get("universal_offset", 0)
    size = min((len(data) - base), *([s["universal_offset"] - base for s in slices if s.get("universal_offset", -1) > base] or [len(data) - base]))
    space = VirtualAddressSpace(tuple(image["segments"]))
    _require(bool(image["segments"]), "image has no segments")
    entry = image["entry"]
    if entry:
        vm = space.file_to_vm(entry["entryoff"])
        _require(vm is not None and bool(space.segment_for_vm(vm)["initprot"] & 4), "entry point outside executable segment")
        entry = {**entry, "vmaddr": vm}
    def payload(info):
        offset, length = info["offset"], info["size"]
        _require(offset <= size and length <= size - offset, "linkedit payload outside slice")
        return data[base + offset:base + offset + length]
    exports = []
    if "exports" in image["linkedit"]:
        exports = parse_exports(payload(image["linkedit"]["exports"]))
    elif image["dyld_info"] and image["dyld_info"]["export"]["size"]:
        exports = parse_exports(payload(image["dyld_info"]["export"]))
    chained = _chained_metadata(payload(image["linkedit"]["chained_fixups"])) if "chained_fixups" in image["linkedit"] else None
    initializers = []
    for seg in image["segments"]:
        for section in seg["sections"]:
            if section["flags"] & 255 == 9:  # S_MOD_INIT_FUNC_POINTERS
                _require(section["size"] % 8 == 0, "misaligned initializer pointer section")
                for at in range(section["offset"], section["offset"] + section["size"], 8):
                    _require(at + 8 <= size, "initializer pointer outside slice")
                    initializers.append(struct.unpack_from("<Q", data, base + at)[0])
    return {"architecture": image["architecture"], "platform": image["platform"], "segments": image["segments"],
            "entry": entry, "dependencies": image["dependencies"], "rpaths": image["rpaths"],
            "exports": exports, "chained_fixups": chained, "initializers": initializers,
            "unresolved_imports": chained["imports"] if chained else [],
            "imports_enumerated": bool(chained),
            "virtual_address_space": space, "executable_mapping": False}
