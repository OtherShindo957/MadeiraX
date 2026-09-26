import plistlib
import struct
import tempfile
import unittest
from pathlib import Path

from madeira_x.macho import MachOError, inspect, inspect_path
from madeira_x.scanner import scan


def command(kind, body=b""):
    return struct.pack("<II", kind, 8 + len(body)) + body


def fixture():
    build = command(0x32, struct.pack("<4I", 1, 0x000D0000, 0x000F0000, 0))
    name = b"/System/Library/Frameworks/Metal.framework/Metal\0"
    dylib = command(0xC, struct.pack("<4I", 24, 0, 0, 0) + name)
    commands = build + dylib
    header = struct.pack("<8I", 0xFEEDFACF, 0x0100000C, 0, 2, 2, len(commands), 0, 0)
    return header + commands


class MachOTests(unittest.TestCase):
    def test_thin_mac_and_dependency(self):
        item = inspect(fixture())["slices"][0]
        self.assertEqual((item["architecture"], item["platform"], item["minimum_os"]), ("arm64", "macOS", "13.0.0"))
        self.assertIn("Metal.framework", item["dependencies"][0]["path"])

    def test_universal_binary(self):
        data = fixture()
        fat = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">5I", 0x0100000C, 0, 28, len(data), 0) + data
        self.assertEqual(inspect(fat)["slices"][0]["universal_offset"], 28)

    def test_bundle_and_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "Demo.app"
            executable = bundle / "Contents" / "MacOS" / "Demo"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(fixture())
            (bundle / "Contents" / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "Demo"}))
            self.assertEqual(inspect_path(bundle)["slices"][0]["architecture"], "arm64")
            self.assertTrue(scan(bundle)["slices"][0]["detected_dependencies"]["Metal"])

    def test_rejects_malformed_commands(self):
        data = bytearray(fixture())
        struct.pack_into("<I", data, 36, 0xFFFFFFFF)
        with self.assertRaises(MachOError):
            inspect(bytes(data))

    def test_rejects_slice_outside_file(self):
        data = struct.pack(">II5I", 0xCAFEBABE, 1, 0x0100000C, 0, 9999, 40, 0)
        with self.assertRaises(MachOError):
            inspect(data)


if __name__ == "__main__":
    unittest.main()
