# C# Security Pattern Scanner

A static analysis tool for identifying security vulnerabilities and secure coding patterns in C#/.NET applications.

## Features

- Scans for 17 vulnerability categories
- Identifies both vulnerable patterns and secure implementations
- Supports .NET Framework, .NET Core, and ASP.NET applications
- Separate secrets scanning mode for configuration files
- Multiple output modes (all findings, vulnerabilities only, secure patterns only)
- Color-coded terminal output with risk levels
- YAML-based signatures for easy customization
- Detailed text report generation

## Installation

### Requirements

- Python 3.6+
- PyYAML library

### Setup

```bash
git clone https://github.com/yourusername/csharp-security-scanner.git
cd csharp-security-scanner

pip install pyyaml

chmod +x scanner.py
```

## Usage

### Basic Scan

```bash
python3 scanner.py /path/to/csharp/project
```

### Command Line Options

```
Usage: scanner.py [OPTIONS] <target_directory>

Options:
    -o, --output FILE      Output file (default: security_review_TIMESTAMP.txt)
    -S, --secrets          Also scan config files for hardcoded secrets
    -f, --findings         Output only vulnerabilities and review items
    -s, --secure-patterns  Output only secure coding patterns
    --signatures DIR       Custom signatures directory
    -h, --help             Show help
```

### Scan Modes

**Default Mode**: Scans code files only (.cs, .aspx, .cshtml, .razor) for all vulnerability patterns.

```bash
python3 scanner.py /path/to/project
```

**Secrets Mode (-S)**: Additionally scans configuration files (.config, .json, .yaml, .xml, .env) for hardcoded credentials and secrets.

```bash
python3 scanner.py -S /path/to/project
```

### Output Modes

**All Results** (default): Shows both secure patterns and potential vulnerabilities.

```bash
python3 scanner.py /path/to/project
```

**Findings Only (-f)**: Shows only HIGH, MEDIUM, and REVIEW items. Useful for vulnerability reports.

```bash
python3 scanner.py -f /path/to/project
```

**Secure Patterns Only (-s)**: Shows only secure coding patterns found. Useful for compliance evidence.

```bash
python3 scanner.py -s /path/to/project
```

### Examples

```bash
# Full scan with secrets, findings only, custom output
python3 scanner.py -S -f -o vulnerabilities.txt /path/to/project

# Quick vulnerability check
python3 scanner.py -f ./src

# Identify secure coding patterns only
python3 scanner.py -s -o secure_patterns.txt ./src

# Use custom signatures
python3 scanner.py --signatures /path/to/custom/signatures /path/to/project
```

## Supported Vulnerability Categories

| Category | Description |
|----------|-------------|
| SQL Injection | String concatenation, interpolation, dynamic LINQ, raw SQL |
| Cross-Site Scripting (XSS) | Html.Raw, Response.Write, disabled validation |
| Path Traversal | Unsanitized file operations, zip slip |
| Cryptography | Weak algorithms (MD5, SHA1, DES), hardcoded keys, insecure TLS |
| Insecure Deserialization | BinaryFormatter, TypeNameHandling, SoapFormatter |
| XML External Entity (XXE) | XmlTextReader, DTD processing enabled |
| Server-Side Request Forgery | Unvalidated URL fetching |
| Cross-Site Request Forgery | Missing anti-forgery tokens |
| Command Injection | Process.Start with user input, shell execution |
| Sensitive Data Exposure | Hardcoded credentials, API keys, connection strings |
| Authentication Issues | Weak password handling, JWT validation disabled |
| Logging Vulnerabilities | Stack traces in responses, sensitive data in logs |
| Security Headers | Missing HSTS, CSP, X-Frame-Options |
| Insecure Configuration | CORS wildcards, directory browsing |
| User Input Sources | Entry points for taint analysis |
| Routing | Attack surface mapping |
| Memory/Reflection | Unsafe code, reflection usage |

## Project Structure

```
csharp-security-scanner/
├── scanner.py              # Main scanner script
├── signatures/             # YAML signature files
│   ├── sqli.yaml          # SQL Injection patterns
│   ├── xss.yaml           # XSS patterns
│   ├── crypto.yaml        # Cryptography patterns
│   ├── deserialization.yaml
│   ├── xxe.yaml
│   ├── ssrf.yaml
│   ├── csrf.yaml
│   ├── cmdi.yaml
│   ├── path_traversal.yaml
│   ├── secrets.yaml
│   ├── auth.yaml
│   ├── logging.yaml
│   ├── headers.yaml
│   ├── config.yaml
│   ├── input.yaml
│   ├── routing.yaml
│   └── memory.yaml
├── test-codebase/          # Test files with vulnerable/secure patterns
├── README.md
├── CONTRIBUTING.md
└── LICENSE
```

## Signature Format

Signatures are defined in YAML files for easy customization:

```yaml
name: SQL Injection
description: Detects SQL injection vulnerabilities

secure:
  - id: ef_linq
    name: Entity Framework LINQ
    pattern: '\.(Where|FirstOrDefault)\s*\([^"]*=>'
    description: Safe parameterized LINQ queries

vulnerable:
  - id: sql_concat
    name: SQL String Concatenation
    pattern: '(SELECT|INSERT|UPDATE|DELETE).*"\s*\+'
    risk: HIGH
    description: String concatenation in SQL queries
    remediation: Use parameterized queries or ORM
```

## Output Format

### Terminal Output

The scanner provides color-coded terminal output:

- RED: HIGH risk findings (immediate attention required)
- YELLOW: MEDIUM risk and REVIEW items
- GREEN: Secure patterns found
- CYAN: Informational messages

### Report File

The generated text report includes:

1. Scan metadata (target, timestamp, settings)
2. Findings grouped by category with descriptions and remediation advice
3. File path, line number, and matching code for each finding
4. Summary statistics with risk breakdown

## Risk Levels

| Level | Description |
|-------|-------------|
| HIGH | Confirmed vulnerability pattern |
| MEDIUM | Likely vulnerability or weak pattern |
| REVIEW | Requires manual verification |
| GOOD | Secure coding pattern |

## Sample Report Output

Detailed text report organized by vulnerability category. Each finding includes the risk level, line number, file path, and the actual code snippet.

```
========== SQL Injection ==========

[!] Security Issues

### SQL String Concatenation ###
Description: String concatenation in SQL queries
Remediation: Use parameterized queries or ORM

[HIGH] - Line 23 - Controllers/UserController.cs ==> var query = "SELECT * FROM users WHERE id = " + userId;
[HIGH] - Line 45 - Services/DataService.cs ==> cmd.CommandText = "DELETE FROM logs WHERE date < '" + date + "'";

### String.Format SQL ###
Description: String.Format with SQL queries
Remediation: Use parameterized queries

[MEDIUM] - Line 67 - Services/DataService.cs ==> String.Format("UPDATE users SET name = '{0}'", name);

[✔] Secure Patterns

### Entity Framework LINQ ###
Description: Safe parameterized LINQ queries

[GOOD] - Line 12 - Services/UserService.cs ==> var user = _context.Users.FirstOrDefault(u => u.Id == id);
[GOOD] - Line 34 - Services/UserService.cs ==> var results = _context.Products.Where(p => p.Price > minPrice);
```

## File Types Scanned

### Code Files (Default)

- `.cs` - C# source files
- `.aspx` - ASP.NET Web Forms pages
- `.ascx` - ASP.NET user controls
- `.cshtml` - Razor views
- `.razor` - Blazor components

### Configuration Files (with -S flag)

- `.config` - XML configuration (Web.config, App.config)
- `.json` - JSON configuration (appsettings.json)
- `.yaml` / `.yml` - YAML configuration
- `.xml` - XML files
- `.env` - Environment files
- `.ini` - INI configuration
- `.properties` - Properties files

## Testing

A test codebase is included in the `test-codebase/` directory with intentionally vulnerable and secure code patterns.

```bash
python3 scanner.py -S test-codebase/
```

## Limitations

- Static analysis only - does not execute code
- Pattern-based detection - may produce false positives
- Does not trace data flow across methods
- Limited to patterns defined in signatures
- Cannot detect business logic vulnerabilities

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding new signatures.

## License

MIT License - See LICENSE file for details.
