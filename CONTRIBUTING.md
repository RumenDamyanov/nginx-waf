# Contributing to nginx-waf

Thank you for your interest in contributing to nginx-waf! This project is in early experimental stages, and community input is valuable.

## ⚠️ Project Status

This project is **experimental and not production-ready**. We're building the foundation and welcome:

- Ideas and suggestions
- Bug reports
- Documentation improvements
- Code contributions
- Testing on different platforms

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use a clear, descriptive title
3. Include:
   - nginx version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs

### Suggesting Features

1. Open a Discussion (not an Issue) for feature ideas
2. Describe the use case and problem it solves
3. Consider if it fits the v1.0 scope (see README)
4. Be open to "future version" responses

### Code Contributions

#### Before You Start

1. Check open issues for existing discussions
2. For significant changes, open an issue first
3. Read `.cursor/instructions.md` for technical guidelines

#### Development Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Follow nginx coding conventions (K&R style)
4. Use nginx memory pools only (no malloc/free)
5. Test your changes thoroughly
6. Update documentation if needed

#### Commit Messages

Use clear, descriptive commit messages:

```
Add waf_mode directive for blacklist/whitelist selection

- Implement directive handler for waf_mode
- Add mode field to configuration structure
- Update merge logic for context inheritance
- Add tests for both modes
```

#### Pull Request Process

1. Ensure all tests pass
2. Update relevant documentation
3. Keep PRs focused and small
4. Reference related issues
5. Be responsive to feedback

### Documentation Contributions

Documentation improvements are always welcome:

- Fix typos and unclear wording
- Add examples
- Improve README sections
- Translate documentation

### Testing Contributions

We especially need help with:

- Testing on different nginx versions (1.24+)
- Testing on different distributions
- Performance testing
- Security review

## Code Standards

### C Code (nginx module)

- Follow nginx coding conventions
- Use nginx memory pools exclusively
- Handle all error conditions
- Add appropriate log messages
- No external dependencies beyond nginx

### Documentation

- Keep README.md concise
- Use clear, simple language
- Include practical examples
- Update when features change

## What We're NOT Looking For (Yet)

To keep the project focused, we're currently not accepting:

- API implementations (planned for v2.0)
- Web UI implementations (planned for v2.0)
- OpenResty/Lua extensions (planned for v2.0)
- Major architectural changes
- Features outside v1.0 scope

These are all great ideas for future versions!

## Communication

- **GitHub Issues**: Bug reports, specific problems
- **GitHub Discussions**: Ideas, questions, general discussion
- **Email**: security@rumenx.com for security issues only

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the BSD 3-Clause License.

---

Thank you for helping make nginx-waf better! 🙏
