# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Types of changes

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

## [Unreleased]

## [0.3.8] - 2025-05-05

### Changed
- Update .release-version with version and build ID

## [0.3.7] - 2025-05-05

### Changed
- Added release 0.3.7; (#98)
- Update .release-version with version and build ID
- Update .release-version with version and build ID [skip ci]

### Fixed
- Fix/issues (#122)
- Gh actions params with conditions; (#121)
- Gh actions params; (#120)
- Gh-actions condition; (#118)
- Gh-actions cycle; (#117)
- Minimal contents permissions; (#116)
- Remote repo url; (#123)
- Remove skip ci status; (#119)
- Revert release version; (#124)
- Token permissions via PAT; (#115)

## [0.3.6] - 2025-04-27

### Changed
- Added new release with lots of changes and improvements; (#85)
- Update .release-version with version and build ID

### Fixed
- Fix actions version and revert release version; (#88)

### Security
- Fix critical vuln - CVE-2025-22871; (#89)

## [0.3.5] - 2025-04-06

### Changed
- Update .release-version with version and build ID

### Security
- Security updates; improve stability; added benchmark arguments in console; (#72) (#73)

## [0.3.4] - 2025-04-05

### Changed
- Update .release-version with version and build ID

### Security
- A lot of fixes with security; masked debug info; improve version output; upd README; (#69) (#71)

## [0.3.3] - 2025-04-03

### Changed
- Update .release-version with version and build ID

### Security
- Add .nancy-ignore for CVE-2025-22870; (#67)

## [0.3.2] - 2025-04-03

### Changed
- Update .release-version with version and build ID

### Fixed
- CI and minor changes; (#66)

## [0.3.1] - 2025-04-03

### Changed
- Update .release-version with version and build ID

### Security
- [SEC] - bump CI syntax and fix vulns, perms;  (#64)

## [0.3.0] - 2025-04-03

### Changed
- Update .release-version with version and build ID

### Security
- Fix automated security scanning workflows; (#62)

## [0.2.9] - 2025-04-03

### Changed
- Update .release-version with version and build ID

### Security
- Security enhance and up to test covers almost 80%; (#61)

## [0.2.8] - 2024-12-11

### Changed
- Update .release-version with version and build ID

### Fixed
- Fixes CI mistakes; bump all actions; (#48)

### Security
- Update security CI; added common badges; (#47)

## [0.2.7] - 2024-12-10

### Changed
- Update .release-version with version and build ID

### Security
- Added strong ciphers and security enhance; fixes README mistakes; added simple tests for benchmarks; LICENSE; added dry-run functionality to show the original and modified lines with line numbers, improved processYamlFile to handle dry-run display effectively. (#46)

## [0.2.6] - 2024-12-10

### Added
- [feature/env blocks] - realized labels for encrypted lines with condition check; (#44)

### Changed
- Update .release-version with version and build ID

## [0.2.5] - 2024-11-20

### Changed
- Update .release-version with version and build ID

### Security
- Bump step-security/harden-runner from 2.10.1 to 2.10.2 (#37)

## [0.2.4] - 2024-11-19

### Added
- Feature/docs (#36)

### Changed
- Update .release-version with version and build ID

## [0.2.3] - 2024-11-18

### Changed
- Bump github/codeql-action from 3.27.2 to 3.27.4 (#34)
- Update .release-version with version and build ID

## [0.2.2] - 2024-11-15

### Added
- [feature/encryption] - add functional tests with 80%+ coverage; update components and fix encryption bugs (#35)

### Changed
- Update .release-version with version and build ID

## [0.2.1] - 2024-11-12

### Changed
- Bump github/codeql-action from 3.27.1 to 3.27.2 (#32)
- Update .release-version with version and build ID

## [0.2.0] - 2024-11-08

### Changed
- Bump golang from 1.23.2-alpine to 1.23.3-alpine (#30)
- Update .release-version with version and build ID

## [0.1.9] - 2024-11-08

### Changed
- Bump github/codeql-action from 3.27.0 to 3.27.1 (#31)
- Update .release-version with version and build ID

## [0.1.8] - 2024-11-06

### Added
- Feature/arch (#28)

### Changed
- Update .release-version with version and build ID

### Fixed
- Revert tag and fix release ci; (#29)

## [0.1.7] - 2024-11-01

### Changed
- Bump actions/dependency-review-action from 4.3.4 to 4.4.0 (#26)
- Update .release-version with version and build ID

## [0.1.6] - 2024-11-01

### Changed
- Bump docker/build-push-action from 3 to 6 (#25)
- Update .release-version with version and build ID

## [0.1.5] - 2024-11-01

### Changed
- Update .release-version with version and build ID

### Fixed
- Ignore files; (#27)

## [0.1.4] - 2024-11-01

### Changed
- Ignore files; (#24)
- Update .release-version with version and build ID

## [0.1.3] - 2024-10-29

### Changed
- Update .release-version with version and build ID
- Update README; (#23)

## [0.1.2] - 2024-10-29

### Added
- Added CI build for ARM-based devices; (#21)

### Changed
- Added permission for actions; (#16)
- Attempt to escape arguments to pass correct information; (#19)
- Ideas/feature cmd (#8)
- Release trigger; (#15)
- Update .release-version with version  and build ID
- Update .release-version with version and build ID
- Update .release-version with version v0.1.2 and build ID

### Fixed
- Actions deprecated version; (#10)
- Added trigger for re-run builds; (#13)
- CI release logics; (#12)
- Escape solution; (#20)
- Fix release version before release stage; (#9)
- Fix/version syntax (#18)
- Formatting escape; (#17)
- Re-use tag name in separate jobs; (#11)
- Release outputs and debug info; (#22)
- Trigger runs; (#14)

## [0.1.1] - 2024-10-29

### Added
- Add binary to git
- Add exit for encode
- Add readme
- Init
- Initial commit
- Refactor code and minor fixes with envs; (#1)

### Changed
- Change cipher to AES256 CBC, helm 3 compatibility
- Debug
- Ideas/build fixes (#3)
- Ideas/ci settings (#6)
- MVP ready
- New file .space.kts
- Prerelease fixes
- Small refactor algorithm
- Some fix
- Some fixes
- Update README.md

### Removed
- Delete idea
- Delete yed
- Delete yed.exe

### Fixed
- Fix comment convertation
- Fix commit, add prefix check
- Fix readme
- Fixes env line processing; (#2)
- Stage with tag version; (#7)
- [fix] fix decryption handling for lines with comments and quotes in YAML processing; (#5)


[Unreleased]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.8...HEAD
[0.3.8]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.7...v0.3.8
[0.3.7]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.6...v0.3.7
[0.3.6]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.9...v0.3.0
[0.2.9]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.9...v0.2.0
[0.1.9]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.8...v0.1.9
[0.1.8]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.7...v0.1.8
[0.1.7]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.6...v0.1.7
[0.1.6]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Gosayram/yaml-encrypter-decrypter/compare/a2d60cb6608e86555ebe67ad00cfd729e6ac6af6...v0.1.1
