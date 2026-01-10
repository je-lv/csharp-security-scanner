#!/usr/bin/env python3
"""
C# Security Pattern Scanner v1.0.0

A static analysis tool for identifying security vulnerabilities
and secure coding patterns in C#/.NET applications.
"""

import argparse
import os
import re
import sys
import yaml
from datetime import datetime
from pathlib import Path
from collections import defaultdict

VERSION = "1.0.0"

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
NC = '\033[0m'
RED_BOLD = '\033[1;31m'
YELLOW_BOLD = '\033[1;33m'


class SignatureLoader:
    """Loads vulnerability signatures from YAML files."""
    
    def __init__(self, signatures_dir):
        self.signatures_dir = Path(signatures_dir)
        self.categories = {}
    
    def load_all(self):
        """Load all signature files from the signatures directory."""
        if not self.signatures_dir.exists():
            print(f"{RED_BOLD}[!]{NC} Signatures directory not found: {self.signatures_dir}")
            sys.exit(1)
        
        for yaml_file in self.signatures_dir.glob("*.yaml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    category_id = yaml_file.stem
                    self.categories[category_id] = data
            except Exception as e:
                print(f"{YELLOW}[!]{NC} Error loading {yaml_file}: {e}")
        
        return self.categories


class Scanner:
    """Main security scanner class."""
    
    def __init__(self, target, output=None, secrets=False, mode="all", signatures_dir=None):
        self.target = Path(target)
        self.secrets = secrets
        self.mode = mode
        self.output = output or f"security_review_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.buffer = []
        
        # Findings counters by category
        self.high = defaultdict(int)
        self.medium = defaultdict(int)
        self.review = defaultdict(int)
        self.good = defaultdict(int)
        
        # Store findings for formatted output
        self.category_findings = defaultdict(lambda: {"vulnerable": [], "secure": []})
        
        # Load signatures
        if signatures_dir is None:
            script_dir = Path(__file__).parent
            signatures_dir = script_dir / "signatures"
        
        loader = SignatureLoader(signatures_dir)
        self.signatures = loader.load_all()
        
        if not self.signatures:
            print(f"{RED_BOLD}[!]{NC} No signatures loaded")
            sys.exit(1)

    def print_good(self, msg):
        print(f"{GREEN}[✔]{NC} {msg}")

    def print_warning(self, msg):
        print(f"{YELLOW}[!]{NC} {msg}")

    def print_info(self, msg):
        print(f"{CYAN}[*]{NC} {msg}")

    def print_section(self, title):
        print(f"\n{BLUE}--- {title} ---{NC}\n")

    def print_category(self, title):
        print(f"\n{YELLOW}========== {title} =========={NC}\n")

    def get_extensions(self, file_type):
        """Get file extensions based on scan type."""
        code_exts = ['.cs', '.aspx', '.ascx', '.cshtml', '.razor']
        config_exts = ['.config', '.json', '.yaml', '.yml', '.xml', '.env', '.ini', '.properties']
        
        if file_type == "secrets":
            return code_exts + config_exts
        return code_exts

    def find_files(self, file_type="code"):
        """Find all files matching the given type."""
        extensions = self.get_extensions(file_type)
        files = []
        for ext in extensions:
            files.extend(self.target.rglob(f"*{ext}"))
        return files

    def should_output(self, risk):
        """Determine if finding should be included in output based on mode."""
        if self.mode == "all":
            return True
        if self.mode == "findings":
            return risk in ("HIGH", "MEDIUM", "REVIEW")
        if self.mode == "secure":
            return risk == "GOOD"
        return True

    def get_risk_label(self, risk):
        """Get display label for risk level."""
        return risk

    def scan_pattern(self, sig_id, name, pattern, risk, category, file_type="code", description="", remediation=""):
        """Scan for a specific pattern across files."""
        matches = []
        try:
            regex = re.compile(pattern)
        except re.error as e:
            self.print_warning(f"Invalid regex for {name}: {e}")
            return 0
        
        for filepath in self.find_files(file_type):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, 1):
                        if regex.search(line):
                            rel_path = str(filepath)
                            matches.append({
                                "file": rel_path,
                                "line": line_num,
                                "code": line.strip(),
                                "risk": risk
                            })
            except Exception:
                pass
        
        count = len(matches)
        
        # Update counters
        counter_map = {
            "HIGH": self.high,
            "MEDIUM": self.medium,
            "REVIEW": self.review,
            "GOOD": self.good
        }
        counter_map.get(risk, self.review)[category] += count
        
        # Store findings for later formatting
        if count > 0:
            finding = {
                "name": name,
                "description": description,
                "remediation": remediation,
                "risk": risk,
                "matches": matches
            }
            
            if risk == "GOOD":
                self.category_findings[category]["secure"].append(finding)
            else:
                self.category_findings[category]["vulnerable"].append(finding)
        
        # Print results to terminal
        if count > 0:
            if risk == "HIGH":
                print(f"{RED_BOLD}[✗] {name}: {count} found (HIGH){NC}")
            elif risk == "MEDIUM":
                print(f"{YELLOW_BOLD}[!] {name}: {count} found (MEDIUM){NC}")
            elif risk == "GOOD":
                self.print_good(f"{name}: {count} found")
            else:
                print(f"{YELLOW}[?] {name}: {count} found (REVIEW){NC}")
        
        return count

    def scan_category(self, category_id, category_data):
        """Scan all patterns in a category."""
        name = category_data.get('name', category_id)
        self.print_category(name)
        
        # Scan secure patterns
        secure = category_data.get('secure', [])
        if secure:
            for sig in secure:
                self.scan_pattern(
                    sig_id=sig.get('id', ''),
                    name=sig.get('name', ''),
                    pattern=sig.get('pattern', ''),
                    risk="GOOD",
                    category=category_id,
                    description=sig.get('description', '')
                )
        
        # Scan vulnerable patterns
        vulnerable = category_data.get('vulnerable', [])
        if vulnerable:
            for sig in vulnerable:
                file_type = "code"
                if category_id == "secrets" and self.secrets:
                    file_type = "secrets"
                
                self.scan_pattern(
                    sig_id=sig.get('id', ''),
                    name=sig.get('name', ''),
                    pattern=sig.get('pattern', ''),
                    risk=sig.get('risk', 'REVIEW'),
                    category=category_id,
                    file_type=file_type,
                    description=sig.get('description', ''),
                    remediation=sig.get('remediation', '')
                )

    def format_category_report(self, category_id):
        """Format a category's findings for the text report."""
        findings = self.category_findings[category_id]
        cat_name = self.signatures.get(category_id, {}).get('name', category_id)
        
        lines = [f"\n\n========== {cat_name} ==========\n"]
        
        # Vulnerable patterns section
        if findings["vulnerable"]:
            lines.append("\n[!] Security Issues\n")
            
            for finding in findings["vulnerable"]:
                lines.append(f"\n### {finding['name']} ###\n")
                if finding['description']:
                    lines.append(f"Description: {finding['description']}\n")
                if finding['remediation']:
                    lines.append(f"Remediation: {finding['remediation']}\n")
                lines.append("\n")
                
                for match in finding['matches']:
                    label = self.get_risk_label(finding['risk'])
                    lines.append(f"[{label}] - Line {match['line']} - {match['file']} ==> {match['code']}\n")
        
        # Secure patterns section
        if findings["secure"]:
            lines.append("\n[✔] Secure Patterns\n")
            
            for finding in findings["secure"]:
                lines.append(f"\n### {finding['name']} ###\n")
                if finding['description']:
                    lines.append(f"Description: {finding['description']}\n")
                lines.append("\n")
                
                for match in finding['matches']:
                    lines.append(f"[GOOD] - Line {match['line']} - {match['file']} ==> {match['code']}\n")
        
        return lines

    def print_statistics(self):
        """Print scan statistics and summary."""
        self.print_section("STATISTICS")
        
        code_files = len(self.find_files("code"))
        self.print_info(f"Code files scanned: {code_files}")
        
        if self.secrets:
            all_files = len(self.find_files("secrets"))
            config_files = all_files - code_files
            self.print_info(f"Config files scanned: {config_files}")
        
        print()
        
        # Calculate totals
        total_high = sum(self.high.values())
        total_medium = sum(self.medium.values())
        total_review = sum(self.review.values())
        total_good = sum(self.good.values())
        total_issues = total_high + total_medium + total_review
        
        # Risk summary
        print(f"{CYAN}=== RISK SUMMARY ==={NC}")
        print("-" * 46)
        print(f"HIGH:          {RED_BOLD}{total_high}{NC}")
        print(f"MEDIUM:        {YELLOW_BOLD}{total_medium}{NC}")
        print(f"Review needed: {YELLOW}{total_review}{NC}")
        print(f"Secure:        {GREEN}{total_good}{NC}")
        print("-" * 46)
        print(f"Total issues:  {total_issues}\n")
        
        # Category breakdown
        print(f"{CYAN}=== BY CATEGORY ==={NC}")
        print(f"{'Category':<20} {'HIGH':<6} {'MED':<6} {'REV':<6} GOOD")
        print("-" * 50)
        
        categories = list(self.signatures.keys())
        for cat_id in categories:
            cat_name = self.signatures[cat_id].get('name', cat_id)
            display_name = cat_name[:18] if len(cat_name) > 18 else cat_name
            print(f"{display_name:<20} {self.high[cat_id]:<6} {self.medium[cat_id]:<6} {self.review[cat_id]:<6} {self.good[cat_id]}")
        
        print()
        
        if total_high == 0:
            self.print_good("No HIGH risk vulnerabilities detected")
        else:
            print(f"{RED_BOLD}[✗] {total_high} HIGH risk findings require attention{NC}")

    def write_report(self):
        """Write findings to output file."""
        with open(self.output, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 62 + "\n")
            f.write(f"C# SECURITY REVIEW v{VERSION}\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Secrets Scan: {'Enabled' if self.secrets else 'Disabled'}\n")
            f.write("=" * 62 + "\n")
            
            # Write each category's formatted findings
            for category_id in self.signatures.keys():
                if self.category_findings[category_id]["vulnerable"] or self.category_findings[category_id]["secure"]:
                    lines = self.format_category_report(category_id)
                    if self.should_output_category(category_id):
                        f.writelines(lines)
            
            # Summary
            total_high = sum(self.high.values())
            total_medium = sum(self.medium.values())
            total_review = sum(self.review.values())
            total_good = sum(self.good.values())
            
            f.write("\n\n" + "=" * 62 + "\n")
            f.write("SUMMARY\n")
            f.write("=" * 62 + "\n\n")
            f.write(f"HIGH:          {total_high}\n")
            f.write(f"MEDIUM:        {total_medium}\n")
            f.write(f"Review needed: {total_review}\n")
            f.write(f"Secure:        {total_good}\n")
            f.write(f"\nTotal issues:  {total_high + total_medium + total_review}\n")
            f.write(f"\nCompleted: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    def should_output_category(self, category_id):
        """Check if category should be included in output based on mode."""
        findings = self.category_findings[category_id]
        
        if self.mode == "all":
            return findings["vulnerable"] or findings["secure"]
        elif self.mode == "findings":
            return bool(findings["vulnerable"])
        elif self.mode == "secure":
            return bool(findings["secure"])
        return True

    def run(self):
        """Execute the security scan."""
        # Banner
        print(f"{BLUE}{'=' * 50}")
        print(f"  C# Security Pattern Scanner v{VERSION}")
        print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 50}{NC}\n")
        
        self.print_info(f"Target: {self.target}")
        self.print_info(f"Output: {self.output}")
        self.print_info(f"Signatures: {len(self.signatures)} categories")
        
        if self.secrets:
            print(f"{CYAN}[*]{NC} Secrets scan: {YELLOW_BOLD}ENABLED{NC}")
        else:
            self.print_info("Secrets scan: Disabled (use -S to enable)")
        
        # Scan each category
        for category_id, category_data in self.signatures.items():
            self.scan_category(category_id, category_data)
        
        # Statistics
        self.print_category("SUMMARY")
        self.print_statistics()
        
        # Write report
        self.write_report()
        
        self.print_section("SCAN COMPLETE")
        self.print_good(f"Report saved to: {self.output}")


def main():
    parser = argparse.ArgumentParser(
        description=f"C# Security Pattern Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py /path/to/project
  python3 scanner.py -S -f /path/to/project
  python3 scanner.py -S -o report.txt /path/to/project
        """
    )
    
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("-o", "--output", help="Output report file")
    parser.add_argument("-S", "--secrets", action="store_true",
                        help="Also scan config files for hardcoded secrets")
    parser.add_argument("-f", "--findings", action="store_true",
                        help="Output only vulnerabilities and review items")
    parser.add_argument("-s", "--secure-patterns", action="store_true",
                        help="Output only secure coding patterns")
    parser.add_argument("--signatures", help="Custom signatures directory")
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.target):
        print(f"{RED_BOLD}[!]{NC} Directory not found: {args.target}", file=sys.stderr)
        sys.exit(1)
    
    # Determine output mode
    mode = "all"
    if args.findings:
        mode = "findings"
    elif args.secure_patterns:
        mode = "secure"
    
    # Run scanner
    scanner = Scanner(
        target=args.target,
        output=args.output,
        secrets=args.secrets,
        mode=mode,
        signatures_dir=args.signatures
    )
    scanner.run()


if __name__ == "__main__":
    main()
