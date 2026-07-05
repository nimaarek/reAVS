import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional  # Add this import

from core.models import Finding, Severity


class NativeAnalyzer:
    """Analyzes native libraries (.so files) for security issues"""

    DANGEROUS_FUNCTIONS = {
        "strcpy": "Buffer overflow risk - use strncpy instead",
        "gets": "Buffer overflow risk - use fgets instead",
        "sprintf": "Buffer overflow risk - use snprintf instead",
        "strcat": "Buffer overflow risk - use strncat instead",
        "scanf": "Format string vulnerability - use safe input methods",
        "system": "Command injection risk - avoid using system()",
        "popen": "Command injection risk - use safer alternatives",
    }

    def analyze(self, so_files: List[Path]) -> List[Finding]:
        findings = []

        for so_file in so_files:
            # Extract strings from .so file
            strings = self._extract_strings(so_file)

            # Check for dangerous functions
            for func, risk in self.DANGEROUS_FUNCTIONS.items():
                if func in strings:
                    finding = Finding(
                        title=f"Dangerous Native Function: {func}()",
                        severity=Severity.HIGH,
                        description=f"Native library {so_file.name} uses {func}() which is dangerous",
                        location=str(so_file),
                        recommendation=risk,
                        cwe="CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
                        evidence=[f"Function {func} found in {so_file.name}"],
                    )
                    findings.append(finding)

            # Check for hardcoded strings
            hardcoded = self._find_hardcoded_secrets(strings)
            if hardcoded:
                for secret in hardcoded:
                    finding = Finding(
                        title="Hardcoded Secret in Native Library",
                        severity=Severity.CRITICAL,
                        description=f"Hardcoded secret found in {so_file.name}: {secret[:20]}...",
                        location=str(so_file),
                        recommendation="Remove hardcoded secrets. Use environment variables or "
                        "secure configuration management.",
                        cwe="CWE-798: Use of Hard-coded Credentials",
                        evidence=[f"Secret found: {secret[:50]}"],
                    )
                    findings.append(finding)

        return findings

    def _extract_strings(self, so_file: Path) -> List[str]:
        """Extract strings from a native library using strings command"""
        strings = []
        try:
            # Use system 'strings' command
            result = subprocess.run(
                ["strings", str(so_file)], capture_output=True, text=True
            )
            strings = result.stdout.split("\n") if result.stdout else []
        except (subprocess.SubprocessError, FileNotFoundError):
            # Fallback: simple binary reading
            try:
                with open(so_file, "rb") as f:
                    content = f.read()
                    # Simple string extraction (printable ASCII sequences of length >= 4)
                    strings = re.findall(b"[ -~]{4,}", content)
                    strings = [s.decode("ascii", errors="ignore") for s in strings]
            except Exception:
                pass
        return strings

    def _find_hardcoded_secrets(self, strings: List[str]) -> List[str]:
        """Find potential hardcoded secrets in extracted strings"""
        secret_patterns = [
            r"api[_-]key[=:]\s*[A-Za-z0-9]+",
            r"secret[=:]\s*[A-Za-z0-9]+",
            r"token[=:]\s*[A-Za-z0-9]+",
            r"password[=:]\s*[A-Za-z0-9]+",
            r"credential[=:]\s*[A-Za-z0-9]+",
            r"[A-Za-z0-9+/]{40,}=",  # Base64 encoded strings
        ]

        secrets = []
        for s in strings:
            for pattern in secret_patterns:
                matches = re.findall(pattern, s, re.IGNORECASE)
                if matches:
                    secrets.extend(matches)
        return secrets
