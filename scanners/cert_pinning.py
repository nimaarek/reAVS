import re
from typing import List, Optional

from core.models import Finding, Severity
from scanners.base import BaseScanner


class CertPinningScanner(BaseScanner):
    """Detects certificate pinning implementations and weaknesses"""

    def scan(self) -> List[Finding]:
        findings = []

        # Check for OkHttp pinning
        okhttp_pinning = self._check_okhttp_pinning()
        if okhttp_pinning:
            findings.extend(okhttp_pinning)

        # Check for custom pinning implementations
        custom_pinning = self._check_custom_pinning()
        if custom_pinning:
            findings.extend(custom_pinning)

        # Check for weak pinning configurations
        weak_pinning = self._check_weak_pinning()
        if weak_pinning:
            findings.extend(weak_pinning)

        return findings

    def _check_okhttp_pinning(self):
        """Check for OkHttp certificate pinning"""
        findings = []
        for method in self.get_all_methods():
            if "CertificatePinner" in str(method):
                if "build" in str(method):
                    # Check if pinning is properly configured
                    pins = self._extract_pins(method)
                    if pins and len(pins) == 0:
                        finding = Finding(
                            title="Empty Certificate Pinning Configuration",
                            severity=Severity.MEDIUM,
                            description="CertificatePinner is built but no pins are configured",
                            location=method_name(method),
                            recommendation="Add at least one certificate pin. Consider using multiple "
                            "pins for redundancy (e.g., one production and one backup cert).",
                            cwe="CWE-295: Improper Certificate Validation",
                            evidence=[
                                "CertificatePinner.build() called without adding pins"
                            ],
                        )
                        findings.append(finding)
        return findings

    def _check_custom_pinning(self):
        """Check for custom pinning implementations"""
        findings = []
        for method in self.get_all_methods():
            # Look for custom pinning logic
            if "TrustManager" in str(method) or "X509TrustManager" in str(method):
                if self._is_custom_implementation(method):
                    finding = Finding(
                        title="Custom Certificate Pinning Implementation",
                        severity=Severity.INFO,
                        description="Custom TrustManager implementation detected. Custom pinning "
                        "is error-prone and should be reviewed carefully.",
                        location=method_name(method),
                        recommendation="Use well-tested libraries like OkHttp's CertificatePinner "
                        "instead of implementing custom pinning logic.",
                        cwe="CWE-295: Improper Certificate Validation",
                        evidence=["Custom TrustManager implementation found"],
                    )
                    findings.append(finding)
        return findings

    def _check_weak_pinning(self):
        """Check for weak pinning configurations"""
        findings = []
        # Check for pinning with weak hash algorithms
        weak_hashes = ["MD5", "SHA1"]
        for method in self.get_all_methods():
            for hash_algo in weak_hashes:
                if hash_algo in str(method):
                    finding = Finding(
                        title=f"Weak Hash Algorithm Used for Pinning: {hash_algo}",
                        severity=Severity.HIGH,
                        description=f"Certificate pinning uses {hash_algo} which is cryptographically weak",
                        location=method_name(method),
                        recommendation=f"Replace {hash_algo} with SHA-256 or stronger hash algorithm",
                        cwe="CWE-326: Inadequate Encryption Strength",
                        evidence=[f"Hash algorithm {hash_algo} used for pinning"],
                    )
                    findings.append(finding)
        return findings

    def _extract_pins(self, method):
        """Extract pins from CertificatePinner configuration"""
        # Placeholder - would need to trace builder pattern
        return []

    def _is_custom_implementation(self, method):
        """Check if method is a custom implementation"""
        # Placeholder - would need to check for custom classes
        return True
