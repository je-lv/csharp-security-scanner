# Contributing to C# Security Pattern Scanner

Thank you for your interest in contributing! This guide explains how to add new security signatures.

## Project Structure

```
csharp-security-scanner/
├── scanner.py              # Main scanner logic
├── signatures/             # YAML signature files
│   ├── sqli.yaml          # SQL Injection patterns
│   ├── xss.yaml           # XSS patterns
│   ├── crypto.yaml        # Cryptography patterns
│   └── ...                # Other categories
├── test-codebase/         # Test files
└── README.md
```

## Adding New Signatures

### 1. Choose the Right File

Each vulnerability category has its own YAML file in the `signatures/` directory:

| File | Category |
|------|----------|
| `sqli.yaml` | SQL Injection |
| `xss.yaml` | Cross-Site Scripting |
| `crypto.yaml` | Cryptography |
| `deserialization.yaml` | Insecure Deserialization |
| `xxe.yaml` | XML External Entity |
| `ssrf.yaml` | Server-Side Request Forgery |
| `csrf.yaml` | Cross-Site Request Forgery |
| `cmdi.yaml` | Command Injection |
| `path_traversal.yaml` | Path Traversal |
| `secrets.yaml` | Hardcoded Secrets |
| `auth.yaml` | Authentication |
| `logging.yaml` | Logging Issues |
| `headers.yaml` | Security Headers |
| `config.yaml` | Configuration |
| `input.yaml` | User Input Sources |
| `routing.yaml` | Routing/Endpoints |
| `memory.yaml` | Memory/Reflection |

### 2. Signature Format

Each signature file follows this structure:

```yaml
name: Category Name
description: Brief description of the category

secure:
  - id: unique_identifier
    name: Human Readable Name
    pattern: 'regex_pattern'
    description: What this pattern detects

vulnerable:
  - id: unique_identifier
    name: Human Readable Name
    pattern: 'regex_pattern'
    risk: HIGH|MEDIUM|REVIEW
    description: What this pattern detects
    remediation: How to fix the issue
```

### 3. Writing Regex Patterns

Patterns use Python regex syntax. Tips:

- Escape special characters: `\.` `\(` `\)`
- Use non-capturing groups: `(?:...)`
- Keep patterns focused and specific
- Test patterns before submitting

Example patterns:

```yaml
# Match method calls
pattern: 'MethodName\s*\('

# Match string concatenation
pattern: '"SELECT.*"\s*\+'

# Match attribute usage
pattern: '\[AttributeName\]'

# Match multiple variations
pattern: '(Option1|Option2|Option3)'
```

### 4. Risk Levels

| Level | Use When |
|-------|----------|
| `HIGH` | Direct security vulnerability, likely exploitable |
| `MEDIUM` | Potential vulnerability, context-dependent |
| `REVIEW` | Needs manual review, may be safe |
| `GOOD` | Secure pattern (only for `secure` section) |

### 5. Example: Adding a New Pattern

To add detection for a new vulnerable pattern:

```yaml
# In signatures/sqli.yaml, under vulnerable:
  - id: new_sqli_pattern
    name: New SQL Pattern
    pattern: 'SomeNewMethod\s*\([^)]*\+\s*userInput'
    risk: HIGH
    description: Detects SQL injection via SomeNewMethod
    remediation: Use parameterized queries instead
```

### 6. Testing Your Changes

1. Add a test case to `test-codebase/`:

```csharp
// test-codebase/Services/TestService.cs
public void VulnerableMethod()
{
    SomeNewMethod("SELECT * FROM users WHERE id = " + userInput);
}
```

2. Run the scanner:

```bash
python3 scanner.py -S test-codebase/
```

3. Verify your pattern is detected correctly.

## Creating a New Category

To add an entirely new vulnerability category:

1. Create `signatures/newcategory.yaml`:

```yaml
name: New Category Name
description: What this category detects

secure:
  - id: secure_pattern_1
    name: Secure Pattern
    pattern: 'SecureMethod\s*\('
    description: Safe usage pattern

vulnerable:
  - id: vuln_pattern_1
    name: Vulnerable Pattern
    pattern: 'UnsafeMethod\s*\('
    risk: HIGH
    description: Unsafe usage
    remediation: Use SecureMethod instead
```

2. The scanner automatically loads all `.yaml` files from the signatures directory.

## Pull Request Guidelines

1. One category/feature per PR
2. Include test cases in `test-codebase/`
3. Test your changes locally
4. Update description/remediation fields
5. Follow existing naming conventions

## Questions?

Open an issue for questions or suggestions.
