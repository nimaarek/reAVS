import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


class PersianReporter:
    """Generate Persian Markdown reports from reAVS JSON output"""

    SEVERITY_FA_PERSIAN = {
        "CRITICAL": "🔴 Critical",
        "HIGH": "🟠 High",
        "MEDIUM": "🟡 Medium",
        "LOW": "🟢 Low",
        "INFO": "ℹ️ Info",
    }

    @classmethod
    def generate_report(cls, json_path: Path, output_path: Path = None) -> Path:
        """Generate Persian report from JSON file"""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if output_path is None:
            output_path = (
                json_path.parent
                / f"persian_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            )

        md_content = cls._build_markdown(data)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return output_path

    @classmethod
    def _build_markdown(cls, data: Dict[str, Any]) -> str:
        """Build Markdown content from JSON data"""

        findings = data.get("findings", [])
        metadata = data.get("metadata", {})

        lines = [
            "# 📱 Android APK Security Analysis Report",
            "",
            f"**File Name:** `{metadata.get('apk_name', 'Unknown')}`",
            f"**Analysis Date:** {datetime.now().strftime('%Y/%m/%d %H:%M:%S')}",
            f"**Scan Mode:** {metadata.get('scan_mode', 'Unknown')}",
            f"**Total Findings:** {len(findings)}",
            "",
            "---",
            "",
            "## 📊 Summary by Severity",
            "",
        ]

        severity_count = {}
        for finding in findings:
            sev = finding.get("severity", "INFO")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        for sev, count in severity_count.items():
            persian_sev = cls.SEVERITY_FA_PERSIAN.get(sev, sev)
            lines.append(f"- **{persian_sev}**: {count} finding(s)")

        # Scanner type statistics
        scanner_counts = {}
        for finding in findings:
            scanner = finding.get("scanner", "Unknown")
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1

        if scanner_counts:
            lines.extend(["", "## 🔍 Findings by Scanner Type", ""])
            for scanner, count in sorted(scanner_counts.items()):
                lines.append(f"- **{scanner}**: {count} finding(s)")

        lines.extend(["", "---", "", "## 🔍 Detailed Findings", ""])

        for idx, finding in enumerate(findings, 1):
            lines.extend(cls._format_finding(idx, finding))
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def _format_finding(cls, index: int, finding: Dict[str, Any]) -> List[str]:
        """Format a single finding as Markdown"""

        title = finding.get("title", "Untitled Finding")
        severity = finding.get("severity", "INFO")
        persian_sev = cls.SEVERITY_FA_PERSIAN.get(severity, severity)
        description = finding.get("description", "No description available")
        location = finding.get("location", "Unknown")
        recommendation = finding.get("recommendation", "No recommendation provided")
        cwe = finding.get("cwe", "")
        scanner = finding.get("scanner", "Unknown")
        evidence = finding.get("evidence", [])

        lines = [
            f"### {index}. {title}",
            "",
            f"- **Severity:** {persian_sev}",
            f"- **Location:** `{location}`",
            f"- **Scanner:** `{scanner}`",
        ]

        if cwe:
            lines.append(f"- **CWE:** `{cwe}`")

        lines.extend(
            [
                "",
                f"**Description:**",
                f"> {description}",
                "",
                f"**Recommendation:**",
                f"> {recommendation}",
            ]
        )

        if evidence:
            lines.extend(
                [
                    "",
                    f"**Evidence:**",
                ]
            )
            for item in evidence:
                lines.append(f"> - {item}")

        lines.extend(["", "---", ""])

        return lines
