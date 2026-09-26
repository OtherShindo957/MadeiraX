# Feasibility and evidence

## Confirmed here

- This repository's host-side parser and scanner operate on synthetic Mach-O fixtures. See the unit tests.
- The current environment has Python but no `clang`, `xcodebuild`, macOS SDK, or iOS device. No real Apple binary or iOS code execution has been tested.

## Supported by Apple documentation, not device tested here

- arm64 is shared across Apple platforms, but the target platform and APIs matter. Apple documents platform-specific code-signing constraints and distinct iOS/macOS support for dynamic libraries.
- `LC_BUILD_VERSION` identifies a build platform; parsing it does not make a macOS binary loadable on iOS.
- Apple's JIT entitlement documentation is framed around hardened runtime. Its availability should not be assumed for an arbitrary iOS sideload, and external debugger/JIT tools do not automatically solve signing, dyld, ABI, framework, or sandbox constraints.

References: https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms ; https://developer.apple.com/documentation/bundleresources/placing-content-in-a-bundle ; https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles ; https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon

## Unknown / device test required

- Whether an imported, unmodified and normally signed macOS arm64 executable can be mapped as executable in a sideloaded iOS process under the target signing/debug setup.
- Which macOS ABI, Objective-C, Swift, fixup, TLS, and Metal features can be safely mapped to iOS counterparts for any specific game.
- Whether StikDebug provides an integration API usable by Madeira X. No such API is assumed in code.

## Current blocker

The app has no proven path to execute an imported macOS binary on iOS. An unsigned `.ipa` still needs an installation/signing workflow on a physical device. A loader cannot be claimed until real code-signing, memory mapping, and entry-point experiments pass on that device.
