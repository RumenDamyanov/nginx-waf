# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Core Module (src/)
- Complete nginx dynamic module implementation (~1100 lines)
- Configuration directives:
  - `waf on|off` - Enable/disable WAF per context
  - `waf_mode blacklist|whitelist` - Operation mode
  - `waf_list name path [tags]` - Define named IP lists
  - `waf_enable_lists` - Enable lists by name, tag, or all
  - `waf_disable_lists` - Disable lists in child contexts
  - `waf_log_prefix` - Custom log prefix
- IPv4 and IPv6 support with CIDR ranges
- Radix tree-based IP lookup (O(32) for IPv4, O(128) for IPv6)
- Context inheritance (location > server > http)
- Tag-based list organization and selection
- Enhanced logging with client IP and matched list name
- Input validation for list and tag names

#### Configuration Examples (conf/)
- `examples.conf` - Comprehensive configuration examples
- `test.conf` - Minimal test configuration

#### Sample Lists (lists/)
- `example-blacklist.txt` - Sample blacklist with test IPs
- `example-whitelist.txt` - Sample whitelist with private ranges
- `README.md` - IP list format documentation

#### Development Tools (.development/)
- `build-module.sh` - Build script for Linux
- `Dockerfile.build` - Docker build environment
- `docker-compose.yml` - Docker compose for build/test
- `generate-test-list.sh` - Generate large IP lists for testing
- `test-module.sh` - Module testing script
- `benchmark.sh` - Performance benchmarking script
- `config.env` - Build configuration

#### Documentation
- Project README with experimental status warning
- CONTRIBUTING.md - Contribution guidelines
- CODE_OF_CONDUCT.md - Contributor Covenant
- SECURITY.md - Security policy
- FUNDING.md - Sponsorship information
- LICENSE.md - BSD 3-Clause License
- `.cursor/instructions.md` - Technical documentation
- `.cursor/action-plan.md` - Development roadmap

### Security
- List/tag name validation (alphanumeric, underscore, hyphen only)
- Maximum list file size limit (10MB)
- Graceful handling of invalid IP addresses
- Memory allocation failure handling

## Roadmap

### v0.3.0 (Beta) - Current Target
- OBS packaging (RPM/DEB)
- CI/CD with GitHub Actions
- Full documentation
- Community testing

### v1.0.0 (Stable) - Production Ready
- All core features tested
- Performance benchmarks published
- OBS packages for major distributions
- Comprehensive wiki documentation

### v2.0.0 (Future) - Extensions
- API daemon (separate project)
- Web interface (separate project)
- OpenResty integration (separate project)

---

**License:** BSD 3-Clause License  
**Author:** Rumen Damyanov <contact@rumenx.com>  
**Repository:** <https://github.com/RumenDamyanov/nginx-waf>
