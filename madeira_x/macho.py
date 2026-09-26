"""Bounds-checked Mach-O and universal-binary inspector. Never executes input."""
from __future__ import annotations

import plistlib
import struct
from pathlib import Path


class MachOError(ValueError):
    pass


CPU_NAMES = {0x0100000C: "arm64", 0x01000007: "x86_64"}
PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "macCatalyst", 7: "iOSSimulator", 8: "tvOSSimulator", 9: "watchOSSimulator", 11: "visionOS"}
DEPENDENCY_COMMANDS = {0xC: "load", 0xD: "id", 0x18: "weak", 0x1F: "reexport", 0x23: "upward", 0x20: "lazy"}
MAX_INPUT = 512 * 1024 * 1024


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise MachOError(message)


def _version(value: int) -> str:
    return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"


def _cstring(blob: bytes, start: int) -> str:
    _require(0 <= start < len(blob), "string offset outside command")
    end = blob.find(b"\0", start)
    _require(end >= 0, "unterminated load-command string")
    return blob[start:end].decode("utf-8", "replace")


def _thin(data: bytes, offset: int = 0, length: int | None = None) -> dict:
    length = len(data) - offset if length is None else length
    _require(length >= 32 and 0 <= offset <= len(data) - length, "truncated Mach-O header")
    magic = data[offset:offset + 4]
    endian = "<" if magic == b"\xcf\xfa\xed\xfe" else ">" if magic == b"\xfe\xed\xfa\xcf" else None
    _require(endian is not None, "unsupported Mach-O magic (64-bit required)")
    _, cpu, subtype, filetype, count, size, flags, reserved = struct.unpack_from(endian + "8I", data, offset)
    _require(count <= 100000 and size <= length - 32 and count <= size // 8, "invalid load-command table")
    result = {"architecture": CPU_NAMES.get(cpu, f"unknown ({cpu:#x})"), "cpu_subtype": subtype,
              "file_type": filetype, "platform": None, "minimum_os": None, "sdk": None,
              "dependencies": [], "rpaths": [], "segments": [], "features": [], "unknown_commands": [],
              "entry": None, "linkedit": {}, "dyld_info": None}
    position = offset + 32
    end = position + size
    for _ in range(count):
        _require(position + 8 <= end, "truncated load command")
        cmd, cmdsize = struct.unpack_from(endian + "II", data, position)
        _require(cmdsize >= 8 and cmdsize <= end - position, "invalid load-command size")
        block = data[position:position + cmdsize]
        base = cmd & ~0x80000000
        if cmd == 0x32:  # LC_BUILD_VERSION
            _require(cmdsize >= 24, "truncated LC_BUILD_VERSION")
            platform, minimum, sdk, toolcount = struct.unpack_from(endian + "4I", block, 8)
            _require(toolcount <= (cmdsize - 24) // 8, "truncated build tools")
            result.update(platform=PLATFORMS.get(platform, f"unknown ({platform})"), minimum_os=_version(minimum), sdk=_version(sdk))
        elif cmd in (0x24, 0x25):
            _require(cmdsize >= 16, "truncated legacy version command")
            minimum, sdk = struct.unpack_from(endian + "2I", block, 8)
            if result["platform"] is None:
                result.update(platform="macOS" if cmd == 0x24 else "iOS", minimum_os=_version(minimum), sdk=_version(sdk))
        elif base in DEPENDENCY_COMMANDS:
            _require(cmdsize >= 24, "truncated dylib command")
            name_offset = struct.unpack_from(endian + "I", block, 8)[0]
            _require(name_offset >= 24, "invalid dylib name offset")
            result["dependencies"].append({"kind": DEPENDENCY_COMMANDS[base], "path": _cstring(block, name_offset)})
        elif cmd == 0x8000001C:  # LC_RPATH
            _require(cmdsize >= 12, "truncated rpath command")
            name_offset = struct.unpack_from(endian + "I", block, 8)[0]
            _require(name_offset >= 12, "invalid rpath offset")
            result["rpaths"].append(_cstring(block, name_offset))
        elif cmd == 0x19:  # LC_SEGMENT_64
            _require(cmdsize >= 72, "truncated segment command")
            name = block[8:24].split(b"\0", 1)[0].decode("utf-8", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian + "4Q", block, 24)
            maxprot, initprot, nsects, segflags = struct.unpack_from(endian + "4I", block, 56)
            _require(nsects <= (cmdsize - 72) // 80, "truncated section table")
            _require(fileoff <= length and filesize <= length - fileoff, "segment exceeds Mach-O slice")
            _require(filesize <= vmsize and vmaddr + vmsize <= 1 << 64, "invalid segment VM size")
            sections = []
            for si in range(nsects):
                so = 72 + si * 80
                section = block[so:so + 16].split(b"\0", 1)[0].decode("utf-8", "replace")
                section_segment = block[so + 16:so + 32].split(b"\0", 1)[0].decode("utf-8", "replace")
                addr, secsize, secfileoff, align, reloff, nreloc, secflags = struct.unpack_from(endian + "2Q5I", block, so + 32)
                _require(section_segment == name, "section segment name mismatch")
                _require(addr >= vmaddr and secsize <= vmaddr + vmsize - addr, "section outside segment VM range")
                zerofill = secflags & 0xFF in (1, 0xC, 0x12)
                if not zerofill:
                    _require(secfileoff >= fileoff and secsize <= fileoff + filesize - secfileoff, "section outside file-backed segment")
                sections.append({"name": section, "addr": addr, "size": secsize, "offset": secfileoff, "flags": secflags, "zerofill": zerofill})
            result["segments"].append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize,
                                       "maxprot": maxprot, "initprot": initprot, "flags": segflags, "sections": sections})
        elif cmd == 0x80000028:  # LC_MAIN
            _require(cmdsize >= 24 and result["entry"] is None, "invalid or duplicate LC_MAIN")
            entryoff, stacksize = struct.unpack_from(endian + "2Q", block, 8)
            result["entry"] = {"kind": "LC_MAIN", "entryoff": entryoff, "stacksize": stacksize}
        elif cmd in (0x80000033, 0x80000034):
            _require(cmdsize >= 16, "truncated linkedit command")
            dataoff, datasize = struct.unpack_from(endian + "2I", block, 8)
            _require(dataoff <= length and datasize <= length - dataoff, "linkedit data outside file")
            key = "exports" if cmd == 0x80000033 else "chained_fixups"
            _require(key not in result["linkedit"], "duplicate linkedit command")
            result["linkedit"][key] = {"offset": dataoff, "size": datasize}
            result["features"].append(key)
        elif cmd in (0x22, 0x80000022):  # LC_DYLD_INFO(_ONLY)
            _require(cmdsize >= 48, "truncated dyld info")
            pairs = struct.unpack_from(endian + "10I", block, 8)
            names = ("rebase", "bind", "weak_bind", "lazy_bind", "export")
            info = dict(zip(names, ({"offset": pairs[i], "size": pairs[i + 1]} for i in range(0, 10, 2))))
            for value in info.values():
                _require(value["offset"] <= length and value["size"] <= length - value["offset"], "dyld info outside file")
            result["dyld_info"] = info
            result["features"].append("dyld_info")
        elif cmd in (0x80000034, 0x80000033, 0x80000022, 0x2, 0x1B, 0x1D, 0x80000028, 0x26):
            result["features"].append({0x80000034: "chained_fixups", 0x80000033: "exports_trie", 0x80000022: "dyld_info", 0x2: "symtab", 0x1B: "uuid", 0x1D: "code_signature", 0x80000028: "main", 0x26: "function_starts"}[cmd])
        else:
            result["unknown_commands"].append(f"{cmd:#x}")
        position += cmdsize
    _require(position == end, "load commands do not fill declared table")
    return result


def inspect(data: bytes) -> dict:
    _require(len(data) <= MAX_INPUT, "file exceeds inspection limit (512 MiB)")
    _require(len(data) >= 4, "file too short")
    if data[:4] not in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"):
        return {"slices": [_thin(data)]}
    is64 = data[:4] in (b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")
    endian = ">" if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") else "<"
    _require(len(data) >= 8, "truncated universal header")
    count = struct.unpack_from(endian + "I", data, 4)[0]
    entry_size = 32 if is64 else 20
    _require(count <= 128 and count <= (len(data) - 8) // entry_size, "invalid universal slice table")
    slices = []
    for index in range(count):
        at = 8 + index * entry_size
        cpu, subtype = struct.unpack_from(endian + "2I", data, at)
        start, length = struct.unpack_from(endian + ("2Q" if is64 else "2I"), data, at + 8)
        _require(start >= 8 + count * entry_size and length <= len(data) - start, "universal slice outside file")
        item = _thin(data, start, length)
        _require(item["architecture"] == CPU_NAMES.get(cpu, f"unknown ({cpu:#x})"), "slice architecture mismatch")
        item["universal_offset"] = start
        slices.append(item)
    return {"slices": slices}


def inspect_path(path: Path) -> dict:
    if path.is_dir():
        _require(path.suffix.lower() == ".app", "directory must be a .app bundle")
        plist_path = path / "Contents" / "Info.plist"
        try:
            info = plistlib.loads(plist_path.read_bytes())
        except (OSError, ValueError, TypeError) as error:
            raise MachOError(f"cannot read Contents/Info.plist: {error}") from error
        executable = info.get("CFBundleExecutable")
        _require(isinstance(executable, str) and executable and Path(executable).name == executable, "invalid CFBundleExecutable")
        candidate = path / "Contents" / "MacOS" / executable
        _require(candidate.is_file() and not candidate.is_symlink(), "bundle executable missing or symlinked")
        path = candidate
    _require(path.is_file(), "executable not found")
    _require(path.stat().st_size <= MAX_INPUT, "file exceeds inspection limit (512 MiB)")
    report = inspect(path.read_bytes())
    report["executable"] = str(path)
    return report
