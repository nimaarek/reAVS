import json
from pathlib import Path
from typing import Dict, List, Optional

from core.models import Finding, Severity
from scanners.base import BaseScanner


class ThirdPartyScanner(BaseScanner):
    """Detects and checks third-party libraries for known vulnerabilities"""

    # Sample vulnerability database - in production, use OWASP Dependency Check
    VULN_DB = {
        "okhttp": {
            "3.12.0": ["CVE-2020-12345", "CVE-2020-12346"],
            "3.11.0": ["CVE-2020-12345"],
        },
        "gson": {
            "2.8.6": ["CVE-2020-12347"],
            "2.8.5": ["CVE-2020-12347", "CVE-2020-12348"],
        },
    }

    def scan(self) -> List[Finding]:
        findings = []
        libraries = self._extract_libraries()

        for lib_name, version in libraries.items():
            # Check for known vulnerabilities
            vulns = self._check_vulnerabilities(lib_name, version)
            if vulns:
                finding = Finding(
                    title=f"Vulnerable Library: {lib_name} {version}",
                    severity=Severity.HIGH,
                    description=f"Library {lib_name} version {version} has known vulnerabilities: "
                    f"{', '.join(vulns)}",
                    location=f"Library: {lib_name}",
                    recommendation=f"Update {lib_name} to the latest version. Check release notes "
                    f"for security patches.",
                    cwe="CWE-1104: Use of Unmaintained Third-Party Components",
                    evidence=[
                        f"Found {lib_name} {version} with {len(vulns)} known vulnerabilities"
                    ],
                )
                findings.append(finding)

            # Check for outdated libraries (older than 1 year)
            if self._is_outdated(lib_name, version):
                finding = Finding(
                    title=f"Outdated Library: {lib_name}",
                    severity=Severity.MEDIUM,
                    description=f"Library {lib_name} version {version} is significantly outdated",
                    location=f"Library: {lib_name}",
                    recommendation=f"Update {lib_name} to the latest version for security fixes "
                    f"and improvements.",
                    cwe="CWE-1104: Use of Unmaintained Third-Party Components",
                    evidence=[f"Version {version} is outdated"],
                )
                findings.append(finding)

        return findings

    def _extract_libraries(self):
        """Extract third-party libraries from APK"""
        # Placeholder - would need to analyze DEX files and MANIFEST.MF
        # Sample data:
        return {"okhttp": "3.12.0", "gson": "2.8.6", "retrofit": "2.9.0"}

    def _check_vulnerabilities(self, lib_name, version):
        """Check library version against vulnerability database"""
        if lib_name in self.VULN_DB:
            if version in self.VULN_DB[lib_name]:
                return self.VULN_DB[lib_name][version]
        return []

    def _is_outdated(self, lib_name, version):
        """Check if library version is outdated"""
        # Placeholder - would need to check against latest versions
        # Sample logic:
        outdated_libs = {
            "okhttp": "4.10.0",  # latest
            "gson": "2.10.0",
            "retrofit": "2.10.0",
        }

        if lib_name in outdated_libs:
            # Version comparison - placeholder
            if version.startswith("2.") or version.startswith("3.0"):
                return True
        return False
