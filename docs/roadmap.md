# Next milestones

## Milestone 2 status

The parser now validates 64-bit segment and section bounds and models virtual addresses without mapping memory. `LC_MAIN`, rpaths, dependencies, export tries, chained fixup headers/import names, and initializer pointer sections have host-side support. No real Apple binary was available in this environment; tests use constructed Mach-O fixtures. Apple dyld's public fixup definitions were used for formats: https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h .

Remaining: walk pointer chains by documented format, decode legacy bind/rebase opcodes, validate exports that require resolver payloads, test real Mach-O files, and perform physical iOS memory/signing experiments. `LC_UNIXTHREAD` is not implemented. No imported code executes.

1. Inspect an actual user-provided arm64 macOS CLI Mach-O and compare output to `otool -l` on a Mac.
2. Build a minimal iOS SwiftUI import/scanner shell using the same binary layout semantics and test importing a benign `.app` archive.
3. On a physical iOS 16+ device, probe code signature, `mmap`/`mprotect`, and executable pages for a separately supplied macOS arm64 test image; capture exact OS errors.
4. Only if execution is permitted, add a minimal image mapper, chained-fixup decoder, import resolver, and tiny test entry point. Keep unsupported load commands explicit.
5. After a CLI program runs, expand to Foundation, SDL, and Metal in increasing complexity.

No compatibility score means a game launches. No DRM or entitlement bypass is planned.
