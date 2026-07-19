# Change Log

v1.1.1

- Stricter compiler warnings
- Updated dependencies

v1.1.0

- Changed code so that "hashing" was replaced with "hash"
- Formatting changes
- Improvement in use of std::span for bounds checking benefit
- Switched from memcpy to std::ranged::copy
- Updated dependencies

v1.0.11

- Corrected a bug in SHA384::Result(std::span<std::uint64_t>) that caused
  a buffer overrun
- Removed a few superfluous parentheses
- Changed the HMAC move constructor to assign values during construction
- Switched std::copy or std::copy\_n to std::ranges::copy and std::ranges::copy\_n
  when copying results; std::memcpy is still employed in the code where
  performance is important

v1.0.10

- CMake changes
- Updated dependencies
- Minor changes to support compiling on 32-bit processors without warning

v1.0.9

- Updated library dependencies
- CMake changes to support downstream unit testing

v1.0.8

- Updated library dependencies

v1.0.7

- Updated the dependency libraries
- Made warnings stricter

v1.0.6

- Updated the security utilities library
- Added a missing #include line

v1.0.5

- Added an implementation of SHA-224

v1.0.4

- Updated library dependencies for FreeBSD builds

v1.0.3

- Updated library dependencies

v1.0.2

- Updated library dependencies

v1.0.1

- Updated secutil to 1.0.1 for better Linux compatibility

v1.0.0

- Initial Release
