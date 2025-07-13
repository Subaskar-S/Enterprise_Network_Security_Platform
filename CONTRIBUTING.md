# Contributing to Enterprise Network Security Platform

Thank you for your interest in contributing to the Enterprise Network Security Platform! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Documentation](#documentation)
- [Testing](#testing)
- [Code Style](#code-style)

## Code of Conduct

This project adheres to a code of conduct that we expect all contributors to follow. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a welcoming environment for everyone.

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Git** installed and configured
- **Docker** and **Docker Compose** installed
- **Python 3.9+** for development
- **Node.js 16+** for dashboard development
- **kubectl** and **helm** for Kubernetes deployments (optional)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/enterprise-network-security-platform.git
   cd enterprise-network-security-platform
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/ORIGINAL_OWNER/enterprise-network-security-platform.git
   ```

## Development Setup

### 1. Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Install Python dependencies
cd automation
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install
```

### 2. Start Development Environment

```bash
# Start core services for development
docker-compose -f docker-compose.dev.yml up -d

# Verify services are running
./scripts/monitoring/health-check.sh
```

### 3. IDE Configuration

#### VS Code
Install recommended extensions:
- Python
- Docker
- Kubernetes
- YAML
- GitLens

#### PyCharm
Configure Python interpreter to use the virtual environment created above.

## Contributing Guidelines

### Types of Contributions

We welcome various types of contributions:

- **Bug fixes**: Fix issues in existing functionality
- **Feature enhancements**: Add new features or improve existing ones
- **Documentation**: Improve or add documentation
- **Testing**: Add or improve test coverage
- **Performance**: Optimize performance and efficiency
- **Security**: Enhance security measures and fix vulnerabilities

### Contribution Areas

#### 1. Security Components
- **IDS/IPS Rules**: Custom Suricata rules for threat detection
- **ML Models**: Improve AI-based threat detection algorithms
- **Incident Response**: Enhance automated response capabilities
- **Compliance**: Add support for additional compliance frameworks

#### 2. Infrastructure
- **Service Mesh**: Istio configuration improvements
- **Monitoring**: Enhanced observability and metrics
- **Deployment**: Kubernetes manifests and Helm charts
- **Performance**: Optimization and scaling improvements

#### 3. Integration
- **SIEM Platforms**: Additional SIEM integrations
- **Threat Intelligence**: New threat intelligence sources
- **Communication**: Slack, Teams, email integrations
- **Ticketing**: JIRA, ServiceNow integrations

## Pull Request Process

### 1. Create a Feature Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. Make Changes

- Follow the [code style guidelines](#code-style)
- Add tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 3. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add new threat detection algorithm

- Implement LSTM-based sequence analysis
- Add support for behavioral anomaly detection
- Include comprehensive test suite
- Update documentation

Closes #123"
```

### 4. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create pull request on GitHub
```

### 5. PR Requirements

Your pull request must:

- [ ] Pass all CI/CD checks
- [ ] Include appropriate tests
- [ ] Update documentation if needed
- [ ] Follow code style guidelines
- [ ] Include a clear description of changes
- [ ] Reference related issues

### 6. Review Process

1. **Automated Checks**: CI/CD pipeline runs automatically
2. **Code Review**: Maintainers review your code
3. **Testing**: Additional testing may be performed
4. **Approval**: At least one maintainer approval required
5. **Merge**: Maintainer merges the PR

## Issue Reporting

### Bug Reports

When reporting bugs, please include:

- **Environment**: OS, Docker version, deployment method
- **Steps to Reproduce**: Clear, step-by-step instructions
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Logs**: Relevant log files or error messages
- **Screenshots**: If applicable

### Feature Requests

For feature requests, please provide:

- **Use Case**: Why is this feature needed?
- **Description**: Detailed description of the feature
- **Acceptance Criteria**: How to know when it's complete
- **Alternatives**: Other solutions you've considered

### Issue Templates

Use the provided issue templates:
- Bug Report
- Feature Request
- Security Vulnerability
- Documentation Improvement

## Security Vulnerabilities

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please:

1. Email security@yourcompany.com
2. Include detailed information about the vulnerability
3. Provide steps to reproduce if possible
4. Allow time for assessment and patching

We will acknowledge receipt within 24 hours and provide a timeline for resolution.

## Documentation

### Documentation Standards

- Use clear, concise language
- Include code examples where appropriate
- Keep documentation up-to-date with code changes
- Follow Markdown best practices

### Types of Documentation

1. **API Documentation**: Document all APIs and endpoints
2. **User Guides**: Step-by-step instructions for users
3. **Developer Guides**: Technical documentation for developers
4. **Architecture**: System design and architecture documents
5. **Deployment**: Installation and deployment guides

### Building Documentation

```bash
# Install MkDocs
pip install mkdocs mkdocs-material

# Serve documentation locally
mkdocs serve

# Build documentation
mkdocs build
```

## Testing

### Test Categories

1. **Unit Tests**: Test individual components
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Test system performance
5. **Security Tests**: Test security controls

### Running Tests

```bash
# Run all tests
pytest

# Run specific test category
pytest tests/unit/
pytest tests/integration/
pytest tests/performance/

# Run with coverage
pytest --cov=automation --cov-report=html

# Run security tests
bandit -r automation/
safety check
```

### Test Requirements

- All new features must include tests
- Maintain minimum 80% code coverage
- Tests must be deterministic and reliable
- Include both positive and negative test cases

## Code Style

### Python

We follow PEP 8 with some modifications:

```bash
# Format code
black automation/

# Sort imports
isort automation/

# Lint code
flake8 automation/

# Type checking
mypy automation/
```

### Configuration Files

- **YAML**: Use 2-space indentation
- **JSON**: Use 2-space indentation
- **Shell Scripts**: Follow Google Shell Style Guide

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Test additions or changes
- `chore`: Maintenance tasks

### Pre-commit Hooks

We use pre-commit hooks to ensure code quality:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files
```

## Development Workflow

### 1. Planning

- Discuss major changes in issues first
- Break large features into smaller PRs
- Consider backward compatibility
- Plan for testing and documentation

### 2. Implementation

- Write tests first (TDD approach)
- Implement incrementally
- Keep commits atomic and focused
- Update documentation as you go

### 3. Review

- Self-review your code before submitting
- Respond promptly to review feedback
- Be open to suggestions and improvements
- Test thoroughly before marking as ready

### 4. Deployment

- Ensure CI/CD passes
- Test in staging environment
- Monitor after deployment
- Be available for hotfixes if needed

## Getting Help

### Communication Channels

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Slack**: #security-platform channel (if available)
- **Email**: security-platform@yourcompany.com

### Resources

- [Project Documentation](docs/)
- [API Reference](docs/api/)
- [Architecture Guide](docs/architecture/)
- [Deployment Guide](docs/deployment/)

## Recognition

Contributors will be recognized in:

- **CONTRIBUTORS.md**: List of all contributors
- **Release Notes**: Major contributions highlighted
- **GitHub**: Contributor statistics and graphs

Thank you for contributing to the Enterprise Network Security Platform! Your efforts help make enterprise networks more secure for everyone.

## License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project (MIT License).
