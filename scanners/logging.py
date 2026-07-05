import re
from typing import List, Optional

from core.models import Finding, Severity
from scanners.base import BaseScanner, has_tainted_arg, method_name


class LoggingScanner(BaseScanner):
    """Detects sensitive data leakage through logging"""

    SENSITIVE_PATTERNS = [
        r"(?i)(token|secret|password|passwd|pwd|credential|auth)",
        r"(?i)(email|phone|mobile|address|ssn|social)",
        r"(?i)(credit.?card|cc.?num|card.?number|cvv|cvc)",
        r"(?i)(api.?key|api.?secret|apikey|secret.?key)",
        r"(?i)(jwt|oauth|bearer|access.?token|refresh.?token)",
    ]

    def scan(self) -> List[Finding]:
        findings = []

        for method in self.get_all_methods():
            if self._is_androidx(method):
                continue

            # Check for Log.d(), Log.i(), Log.w(), Log.e(), Log.v()
            log_calls = self._find_log_calls(method)

            for call in log_calls:
                if self._is_sensitive_data(call):
                    finding = Finding(
                        title="Sensitive Data Leakage via Logging",
                        severity=Severity.MEDIUM,
                        description=f"Sensitive data is being logged in {method_name(method)}. "
                        f"Data: {call['data']}",
                        location=method_name(method),
                        recommendation="Remove logging of sensitive data in production builds. "
                        "Use Log.isLoggable() to conditionally log only in debug builds.",
                        cwe="CWE-532: Information Exposure Through Log Files",
                        evidence=[f"Log call at {call['line']}: {call['raw']}"],
                    )
                    findings.append(finding)

        return findings

    def _find_log_calls(self, method):
        """Find all logging calls in a method"""
        log_calls = []
        for instruction in method.get_instructions():
            if instruction.output.startswith("invoke-static"):
                if (
                    "Log.d" in instruction.output
                    or "Log.i" in instruction.output
                    or "Log.w" in instruction.output
                    or "Log.e" in instruction.output
                    or "Log.v" in instruction.output
                ):
                    # Extract the logged data
                    data = self._extract_log_data(instruction)
                    log_calls.append(
                        {
                            "line": instruction.get_line(),
                            "raw": instruction.output,
                            "data": data,
                        }
                    )
        return log_calls

    def _is_sensitive_data(self, call):
        """Check if logged data contains sensitive patterns"""
        data = call["data"]
        for pattern in self.SENSITIVE_PATTERNS:
            if re.search(pattern, data):
                return True
        return False

    def _extract_log_data(self, instruction):
        """Extract data being logged from instruction"""
        # Simplified extraction - in practice, would need to trace register values
        # This is a placeholder for the actual implementation
        return "extracted_log_data"

    def _is_androidx(self, method):
        """Check if method is from AndroidX library"""
        class_name = method.get_class_name()
        return class_name.startswith("androidx.") or class_name.startswith(
            "com.google.android."
        )
