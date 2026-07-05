import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional

from core.models import Finding, Severity
from scanners.base import BaseScanner


class NetworkConfigScanner(BaseScanner):
    """Analyzes network_security_config.xml for security weaknesses"""

    def scan(self) -> List[Finding]:
        findings = []
        config_path = self._find_network_config()

        if not config_path:
            return findings

        try:
            tree = ET.parse(config_path)
            root = tree.getroot()

            # Check for cleartext traffic
            cleartext = root.get("cleartextTrafficPermitted")
            if cleartext == "true":
                finding = Finding(
                    title="Cleartext Traffic Permitted",
                    severity=Severity.HIGH,
                    description="Network Security Config allows cleartext (HTTP) traffic",
                    location=str(config_path),
                    recommendation="Set cleartextTrafficPermitted='false' to enforce HTTPS. "
                    "If you need HTTP for specific domains, use domain-config with "
                    "cleartextTrafficPermitted='true' only for those domains.",
                    cwe="CWE-319: Cleartext Transmission of Sensitive Information",
                    evidence=[
                        f"cleartextTrafficPermitted='{cleartext}' in network_security_config.xml"
                    ],
                )
                findings.append(finding)

            # Check for certificate pinning configuration
            pinning = self._check_pinning_config(root)
            if pinning:
                findings.extend(pinning)

            # Check for debug overrides
            debug_override = root.find(".//debug-overrides")
            if debug_override is not None:
                finding = Finding(
                    title="Debug Overrides Configured",
                    severity=Severity.LOW,
                    description="Network Security Config contains debug overrides that may weaken "
                    "security in debug builds",
                    location=str(config_path),
                    recommendation="Ensure debug overrides are only used in debug builds and not "
                    "accidentally included in release builds.",
                    cwe="CWE-250: Execution with Unnecessary Privileges",
                    evidence=[
                        "debug-overrides section present in network_security_config.xml"
                    ],
                )
                findings.append(finding)

        except ET.ParseError:
            # XML parsing error
            finding = Finding(
                title="Malformed Network Security Config",
                severity=Severity.LOW,
                description="network_security_config.xml could not be parsed",
                location=str(config_path),
                recommendation="Fix the XML syntax errors in network_security_config.xml",
                cwe="CWE-20: Improper Input Validation",
                evidence=["XML parsing error in network_security_config.xml"],
            )
            findings.append(finding)

        return findings

    def _find_network_config(self):
        """Find network_security_config.xml in the APK"""
        # Placeholder - would need to extract and search APK resources
        return None

    def _check_pinning_config(self, root):
        """Check certificate pinning configuration"""
        findings = []
        pinning_configs = root.findall(".//pin-set")

        for pin_set in pinning_configs:
            expiration = pin_set.get("expiration")
            if expiration:
                # Check if expiration is too far in future
                # Placeholder for date parsing
                pass

            # Check pin count
            pins = pin_set.findall("pin")
            if len(pins) < 2:
                finding = Finding(
                    title="Insufficient Certificate Pins",
                    severity=Severity.MEDIUM,
                    description=f"Only {len(pins)} pin(s) configured. Need at least 2 pins for redundancy.",
                    location=str(pin_set),
                    recommendation="Configure at least 2 pins (e.g., one production cert and one backup)",
                    cwe="CWE-295: Improper Certificate Validation",
                    evidence=[f"Only {len(pins)} pins configured"],
                )
                findings.append(finding)

        return findings
