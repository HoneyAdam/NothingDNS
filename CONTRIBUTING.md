# Contributing to NothingDNS

Thank you for your interest in contributing to NothingDNS!

## Quick Start

```bash
# Clone the repository
git clone https://github.com/NothingDNS/NothingDNS.git
cd NothingDNS

# Setup development environment
./scripts/dev-setup.sh

# Run the server
make dev
```

## Development Workflow

### 1. Branch Naming

```
feature/description     # New features
bugfix/description      # Bug fixes
docs/description        # Documentation improvements
refactor/description   # Code refactoring
security/description   # Security-related changes
```

### 2. Making Changes

1. Create a branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make your changes, following the coding standards

3. Run tests:
   ```bash
   make test
   make lint
   ```

4. Commit with a clear message:
   ```bash
   git commit -m "feature: add support for X"
   ```

### 3. Coding Standards

#### Go Code

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Run `gofmt` before committing
- Use `go vet` and `staticcheck`
- Write tests for new functionality

#### File Organization

```
cmd/nothingdns/       # Main application
cmd/dnsctl/           # CLI tool
internal/             # Internal packages (no external imports)
pkg/                  # Public packages (if any)
```

#### Error Handling

- Return errors with context using `fmt.Errorf("operation: %w", err)`
- Handle all errors explicitly
- Use `errors.Is()` and `errors.As()` for error checking

#### Logging

- Use structured logging (`log.Info`, `log.Error`, etc.)
- Include relevant context (request ID, zone name, etc.)
- Don't log sensitive information

### 4. Testing

```bash
# Run all tests
make test

# Run specific package tests
make test-pkg PKG=./internal/cache

# Run with verbose output
make test-verbose

# Run E2E tests
make test-e2e

# Run with race detector
make test-race
```

#### Test Coverage

- New code should include tests
- Aim for > 80% coverage on new packages
- Run `make test-coverage` to generate coverage report

### 5. Documentation

Update documentation when:
- Adding new features
- Changing configuration options
- Modifying API endpoints
- Updating dependencies

Documentation files:
- `docs/*.md` — User-facing documentation
- `internal/*/README.md` — Package documentation
- Code comments — Implementation details

### 6. Git Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat` — New feature
- `fix` — Bug fix
- `docs` — Documentation
- `style` — Formatting
- `refactor` — Refactoring
- `test` — Tests
- `chore` — Build/process changes

Examples:
```
feat(cache): add NSEC aggressive caching

implements RFC 8198 for faster NXDOMAIN responses
```

```
fix(cluster): handle network partition gracefully

Previously, cluster would deadlock. Now uses timeout
for gossip exchanges to detect failed nodes.
```

### 7. Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes with tests
4. **Ensure** all tests pass (`make ci`)
5. **Update** documentation
6. **Submit** a pull request

#### PR Template

```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Testing
How was this tested?

## Checklist
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] PR title follows Conventional Commits
```

### 8. Code Review

- Address reviewer feedback
- Keep PRs focused and small (< 500 lines preferred)
- Reference issues in PR description

### 9. Reporting Issues

Use [GitHub Issues](https://github.com/NothingDNS/NothingDNS/issues) for:
- Bug reports
- Feature requests
- Documentation improvements

For security issues, see [SECURITY.md](../SECURITY.md).

## Resources

- [Architecture](../docs/ARCHITECTURE.md) — System design
- [API Reference](../docs/API_REFERENCE.md) — REST API documentation
- [Configuration](../docs/CONFIG_REFERENCE.md) — Configuration options
- [Troubleshooting](../docs/TROUBLESHOOTING.md) — Common issues

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see [LICENSE](LICENSE)).