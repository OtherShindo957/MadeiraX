# Madeira X

Experimental research into ARM64 macOS game compatibility on iOS. Current milestone: **host-side inspection only**. No macOS binary execution, iOS launcher, or IPA exists yet.

## Inspect a game

```sh
python3 -m madeira_x /path/to/Game.app
python3 -m madeira_x /path/to/MachO
python3 -m madeira_x --prepare /path/to/MachO
python3 -m unittest discover -s tests -v
```

The scanner reads macOS `.app/Contents/Info.plist` and its executable, recognizes thin and universal 64-bit Mach-O slices, and prints architecture, platform, minimum version, dependencies, rpaths, segments, and known load-command markers. Its assessment is intentionally conservative. Input is parsed as data; it is never executed.

Milestone 2 adds a validated, host-side virtual address space, file/VM translation, `LC_MAIN` entry address, export trie parsing, dependency path expansion, and chained-fixup header and import-table inspection. Pointer-chain traversal, legacy bind opcodes, actual relocation application, library loading, and iOS execution are not implemented. `--prepare` only produces metadata.

See [docs/feasibility.md](docs/feasibility.md) for the execution barrier and [docs/roadmap.md](docs/roadmap.md) for device tests. The artwork in `assets/` is the supplied Madeira X logo.

No commercial games or Apple proprietary frameworks are included.
