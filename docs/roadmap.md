# Next milestones

1. Inspect an actual user-provided arm64 macOS CLI Mach-O and compare output to `otool -l` on a Mac.
2. Build a minimal iOS SwiftUI import/scanner shell using the same binary layout semantics and test importing a benign `.app` archive.
3. On a physical iOS 16+ device, probe code signature, `mmap`/`mprotect`, and executable pages for a separately supplied macOS arm64 test image; capture exact OS errors.
4. Only if execution is permitted, add a minimal image mapper, chained-fixup decoder, import resolver, and tiny test entry point. Keep unsupported load commands explicit.
5. After a CLI program runs, expand to Foundation, SDL, and Metal in increasing complexity.

No compatibility score means a game launches. No DRM or entitlement bypass is planned.
