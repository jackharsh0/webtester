# Contributing to WebTester

Thank you for your interest in contributing to WebTester! This document provides guidelines and information for contributors.

## How to Contribute

### 1. Fork the Repository
```bash
# Fork on GitHub, then clone
git clone https://github.com/YOUR_USERNAME/webtester.git
cd webtester
```

### 2. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 3. Make Your Changes
- Add new security checks
- Improve existing functionality
- Fix bugs
- Update documentation

### 4. Test Your Changes
```bash
# Install dependencies
pip install -r requirements.txt

# Test the scanner
python webtester.py https://example.com
```

### 5. Commit and Push
```bash
git add .
git commit -m "Add: Your feature description"
git push origin feature/your-feature-name
```

### 6. Create a Pull Request
- Go to the original repository
- Click "New Pull Request"
- Describe your changes

## Development Guidelines

### Code Style
- Follow PEP 8 for Python code
- Use meaningful variable names
- Add docstrings to functions
- Keep functions focused and small

### Adding New Security Checks

1. **Create the check function** in `scanner.py`:
```python
def check_your_vulnerability(self):
    """Check X: Description of vulnerability."""
    self.stats['checks_run'] += 1
    
    # Your check logic here
    
    # If vulnerability found:
    self._add_finding(
        category='category_name',
        severity='severity_level',  # critical, high, medium, low, info
        title='Vulnerability Title',
        description='Detailed description',
        evidence='Evidence found',
        remediation='How to fix'
    )
    
    # If check passes:
    self.stats['checks_passed'] += 1
```

2. **Add the check to the scan() method**:
```python
checks = [
    # ... existing checks ...
    ("Your check name", self.check_your_vulnerability),
]
```

### Severity Levels

| Level | Description |
|-------|-------------|
| `critical` | Immediate danger, requires urgent fix |
| `high` | Serious vulnerability, should be fixed soon |
| `medium` | Moderate risk, should be addressed |
| `low` | Minor issue, low risk |
| `info` | Informational, not necessarily a problem |

### Testing New Checks

Before submitting, test your check:
```bash
python webtester.py https://testphp.vulnweb.com
```

## Reporting Issues

When reporting bugs, include:
- Python version
- Operating system
- Steps to reproduce
- Expected behavior
- Actual behavior
- Error messages

## Feature Requests

For new features, describe:
- What you want to add
- Why it's useful
- How it should work
- Example use cases

## Pull Request Checklist

- [ ] Code follows project style
- [ ] Changes tested locally
- [ ] Documentation updated
- [ ] No sensitive data committed
- [ ] Commit messages are clear

## Questions?

Feel free to open an issue with your questions!

Thank you for contributing!