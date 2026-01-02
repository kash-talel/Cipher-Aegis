# Contributing to Cipher Aegis

Thank you for your interest in contributing to Cipher Aegis. This document provides guidelines and standards for contributions.

## Code of Conduct

Be professional, respectful, and constructive in all interactions. We aim to maintain a welcoming environment for all contributors.

## Development Environment Setup

1. Fork and clone the repository:
```bash
git clone https://github.com/yourusername/CipherAegis.git
cd CipherAegis
```

2. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

3. Install development dependencies:
```bash
pip install -r requirements.txt
pip install pytest flake8 mypy black
```

## Coding Standards

### Python Style Guide

Follow PEP 8 with these specific requirements:

- Maximum line length: 100 characters
- Use 4 spaces for indentation (no tabs)
- Two blank lines between top-level definitions
- One blank line between method definitions

### Type Hints

All functions must include type hints:

```python
def process_packet(packet: PacketInfo) -> Optional[FlowFeatures]:
    """Process a single packet and return features if flow completes."""
    pass
```

### Documentation

Use Google-style docstrings:

```python
def analyze_flow(features: FlowFeatures) -> Tuple[bool, float, str]:
    """
    Analyze a network flow for anomalies.

    Args:
        features: FlowFeatures object containing flow statistics.

    Returns:
        Tuple containing:
            - is_anomaly: Boolean indicating if flow is anomalous
            - anomaly_score: Float between 0.0 and 1.0
            - threat_level: String ("LOW", "MEDIUM", or "HIGH")

    Raises:
        ValueError: If features contain invalid data.
    """
    pass
```

### Code Formatting

Use Black formatter with default settings:

```bash
black .
```

### Linting

Code must pass flake8 without errors:

```bash
flake8 . --max-line-length=100
```

### Type Checking

Code must pass mypy type checking:

```bash
mypy . --strict
```

## Testing Requirements

### Unit Tests

All new code must include unit tests:

```python
import pytest
from core.features import FeatureExtractor

class TestFeatureExtractor:
    def test_flow_creation(self):
        extractor = FeatureExtractor()
        # Test implementation
        assert extractor is not None

    def test_packet_processing(self):
        # Test packet processing logic
        pass
```

### Running Tests

```bash
pytest tests/ -v --cov=. --cov-report=html
```

Minimum coverage requirement: 80%

### Integration Tests

Test interactions between components:

```python
def test_end_to_end_flow():
    """Test complete pipeline from packet to database."""
    sentinel = NetworkSentinel()
    extractor = FeatureExtractor()
    # Test implementation
```

## Git Workflow

### Branch Naming

Use descriptive branch names:

- Feature: `feature/add-pcap-replay`
- Bug fix: `bugfix/fix-memory-leak`
- Documentation: `docs/update-api-reference`
- Performance: `perf/optimize-flow-extraction`

### Commit Messages

Follow conventional commit format:

```
type(scope): brief description

Detailed explanation of changes if necessary.

Fixes #123
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks

Example:
```
feat(ml): add ensemble model support

Implement voting classifier combining Isolation Forest
with One-Class SVM for improved detection accuracy.

Performance improved by 15% on CICIDS2017 dataset.

Fixes #45
```

### Pull Request Process

1. Update documentation for any API changes
2. Add tests for new functionality
3. Ensure all tests pass
4. Update CHANGELOG.md
5. Request review from maintainers
6. Address review comments
7. Squash commits if requested
8. Maintainer will merge when approved

### Pull Request Template

Include this information:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
Describe testing performed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Commented complex logic
- [ ] Updated documentation
- [ ] Added tests
- [ ] All tests pass
- [ ] No new warnings
```

## Architecture Guidelines

### Modularity

Keep components loosely coupled:

```python
# Good: Clear interface
class FeatureExtractor:
    def process_packet(self, packet: PacketInfo) -> Optional[FlowFeatures]:
        pass

# Bad: Tight coupling
class FeatureExtractor:
    def __init__(self, sentinel: NetworkSentinel):
        self.sentinel = sentinel  # Unnecessary dependency
```

### Error Handling

Use specific exceptions with informative messages:

```python
if not self.is_trained:
    raise RuntimeError(
        "Model is not trained. Call train() with benign traffic samples "
        "before making predictions."
    )
```

### Logging

Use Python logging module:

```python
import logging

logger = logging.getLogger(__name__)

logger.info("Starting packet capture")
logger.warning("High packet drop rate detected: 5%")
logger.error("Database connection failed", exc_info=True)
```

### Performance Considerations

- Use generators for large datasets
- Implement batch processing where applicable
- Profile code for bottlenecks (use cProfile)
- Avoid premature optimization

## Documentation Requirements

### Code Documentation

- All public APIs must have docstrings
- Complex algorithms need inline comments
- Include usage examples in docstrings

### README Updates

Update README.md for:
- New features or components
- API changes
- Configuration options
- Performance improvements

### Changelog

Update CHANGELOG.md following Keep a Changelog format:

```markdown
## [Unreleased]

### Added
- PCAP file replay functionality

### Changed
- Improved ML prediction performance by 20%

### Fixed
- Memory leak in flow aggregation
```

## Issue Reporting

### Bug Reports

Include:
- Python version and OS
- Steps to reproduce
- Expected vs actual behavior
- Error messages and stack traces
- Relevant configuration

### Feature Requests

Include:
- Use case description
- Proposed implementation approach
- Potential challenges
- Alternative solutions considered

## Performance Guidelines

### Benchmarking

For performance-critical changes:

1. Establish baseline metrics
2. Implement optimization
3. Measure improvement
4. Document in PR

Example:
```python
import time

def benchmark_flow_processing():
    start = time.perf_counter()
    # Process 10000 flows
    elapsed = time.perf_counter() - start
    print(f"Processed 10000 flows in {elapsed:.2f}s")
```

### Memory Profiling

Use memory_profiler for memory-intensive code:

```python
from memory_profiler import profile

@profile
def memory_intensive_function():
    # Implementation
    pass
```

## Security Considerations

- Never commit sensitive data (API keys, passwords)
- Validate all external inputs
- Use parameterized SQL queries
- Handle errors securely (no sensitive info in error messages)
- Follow principle of least privilege

## Release Process

Maintainers follow this process for releases:

1. Update version in `__init__.py`
2. Update CHANGELOG.md
3. Create release branch
4. Run full test suite
5. Create tag: `git tag -a v1.0.0 -m "Release 1.0.0"`
6. Push tag: `git push origin v1.0.0`
7. Create GitHub release
8. Build and publish package (if applicable)

## Questions and Support

- GitHub Issues: Technical questions and bug reports
- GitHub Discussions: General questions and ideas
- Email: Contact maintainers for private inquiries

## Recognition

Contributors will be acknowledged in:
- CONTRIBUTORS.md file
- Release notes
- GitHub contributors page

Thank you for contributing to Cipher Aegis.
