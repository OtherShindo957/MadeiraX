import struct
import unittest

from madeira_x.dyld import expand_dependency
from madeira_x.loader import VirtualAddressSpace, parse_exports, prepare_image
from madeira_x.macho import MachOError


def command(kind, payload):
    return struct.pack("<II", kind, 8 + len(payload)) + payload


def image(*, invalid_section=False, overlap=False, invalid_entry=False, exports=None, fixups=None):
    # Two small contiguous file-backed segments, with a deterministic file layout.
    def segment(name, vm, off, size, section=False):
        sect = b""
        if section:
            address = vm + (size + 1 if invalid_section else 0)
            sect = struct.pack("<16s16sQQIIIIIIII", b"__text", name.encode(), address, 16, off, 0, 0, 0, 0, 0, 0, 0)
        body = struct.pack("<16sQQQQIIII", name.encode(), vm, size, off, size, 7, 5 if name == "__TEXT" else 3, int(section), 0)
        return command(0x19, body + sect)
    parts = [command(0x32, struct.pack("<4I", 1, 0xE0000, 0xF0000, 0)),
             segment("__TEXT", 0x100000000, 0, 0x200, True),
             segment("__DATA", 0x100000100 if overlap else 0x100001000, 0x200, 0x100),
             command(0x80000028, struct.pack("<2Q", 0x250 if invalid_entry else 0x180, 0))]
    if exports is not None:
        parts.append(command(0x80000033, struct.pack("<2I", 0x300, len(exports))))
    if fixups is not None:
        parts.append(command(0x80000034, struct.pack("<2I", 0x340, len(fixups))))
    commands = b"".join(parts)
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, len(parts), len(commands), 0, 0)
    assert len(header + commands) <= 0x180
    binary = bytearray(0x400)
    binary[:len(header + commands)] = header + commands
    if exports is not None:
        binary[0x300:0x300 + len(exports)] = exports
    if fixups is not None:
        binary[0x340:0x340 + len(fixups)] = fixups
    return bytes(binary)


class LoaderTests(unittest.TestCase):
    def test_segment_mapping_and_entry(self):
        plan = prepare_image(image())
        space = plan["virtual_address_space"]
        self.assertEqual(plan["entry"]["vmaddr"], 0x100000180)
        self.assertEqual(space.vm_to_file(0x100000180), 0x180)
        self.assertEqual(space.file_to_vm(0x220), 0x100001020)
        self.assertIsNone(space.vm_to_file(0x100002000))
        self.assertFalse(plan["executable_mapping"])

    def test_segment_outside_file(self):
        raw = bytearray(image())
        raw[32 + 24 + 8 + 40:32 + 24 + 8 + 48] = struct.pack("<Q", 0x5000)
        with self.assertRaises(MachOError):
            prepare_image(bytes(raw))

    def test_section_outside_segment(self):
        with self.assertRaisesRegex(MachOError, "section outside"):
            prepare_image(image(invalid_section=True))

    def test_overlapping_vm_segments(self):
        with self.assertRaisesRegex(MachOError, "overlapping VM"):
            prepare_image(image(overlap=True))

    def test_entry_outside_executable_segment(self):
        with self.assertRaisesRegex(MachOError, "entry point"):
            prepare_image(image(invalid_entry=True))

    def test_export_trie(self):
        # root -> _foo, terminal flags=0, address=0x42
        trie = b"\x00\x01_foo\x00\x08\x02\x00\x42\x00"
        self.assertEqual(parse_exports(trie)[0]["name"], "_foo")
        self.assertEqual(prepare_image(image(exports=trie))["exports"][0]["value"], 0x42)

    def test_truncated_export_trie(self):
        for data in (b"\x80", b"\x00\x01foo", b"\x00\x01x\x00\xff"):
            with self.subTest(data=data), self.assertRaises(MachOError):
                parse_exports(data)

    def test_chained_header_metadata(self):
        payload = struct.pack("<8I", 0, 28, 32, 32, 0, 1, 0, 0)
        report = prepare_image(image(fixups=payload))
        self.assertEqual(report["chained_fixups"]["segment_count"], 0)
        self.assertFalse(report["chained_fixups"]["pointer_chains_decoded"])

    def test_bad_chained_offset(self):
        payload = struct.pack("<7I", 0, 999, 28, 28, 0, 1, 0)
        with self.assertRaises(MachOError):
            prepare_image(image(fixups=payload))

    def test_chained_import_name(self):
        # Header (28), starts table (8), import entry (4), string pool.
        payload = struct.pack("<7I", 0, 28, 36, 40, 1, 1, 0) + struct.pack("<I", 0) + b"\0" * 4
        payload += struct.pack("<I", 1) + b"_malloc\0"
        result = prepare_image(image(fixups=payload))
        self.assertEqual(result["unresolved_imports"][0]["name"], "_malloc")
        self.assertTrue(result["imports_enumerated"])

    def test_rpath_resolution(self):
        self.assertEqual(expand_dependency("@rpath/SDL2.framework/SDL2", "/Games/A.app/Contents/MacOS/A",
                         "/Games/A.app/Contents/MacOS/A", ["@loader_path/../Frameworks"]),
                         ["/Games/A.app/Contents/Frameworks/SDL2.framework/SDL2"])

    def test_reject_unsupported_token(self):
        with self.assertRaises(MachOError):
            expand_dependency("@bad/foo", "/app/A", "/app/A", [])


if __name__ == "__main__":
    unittest.main()
