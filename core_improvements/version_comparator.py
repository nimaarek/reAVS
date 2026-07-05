import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List  # Add this import


class VersionComparator:
    """Compare two JSON reports to track security changes across versions"""

    @classmethod
    def compare(
        cls, old_report: Path, new_report: Path, output_path: Path = None
    ) -> Dict[str, Any]:
        """Compare two analysis reports"""
        with open(old_report, "r", encoding="utf-8") as f:
            old_data = json.load(f)
        with open(new_report, "r", encoding="utf-8") as f:
            new_data = json.load(f)

        old_findings = old_data.get("findings", [])
        new_findings = new_data.get("findings", [])

        # Create maps for comparison
        old_map = cls._create_finding_map(old_findings)
        new_map = cls._create_finding_map(new_findings)

        # Identify changes
        added = [f for f in new_findings if f.get("title") not in old_map]
        removed = [f for f in old_findings if f.get("title") not in new_map]
        unchanged = [f for f in new_findings if f.get("title") in old_map]

        # Check for severity changes
        severity_changes = []
        for title, new_finding in new_map.items():
            if title in old_map:
                old_sev = old_map[title].get("severity", "INFO")
                new_sev = new_finding.get("severity", "INFO")
                if old_sev != new_sev:
                    severity_changes.append(
                        {
                            "title": title,
                            "old_severity": old_sev,
                            "new_severity": new_sev,
                        }
                    )

        result = {
            "comparison_date": datetime.now().isoformat(),
            "summary": {
                "old_findings_count": len(old_findings),
                "new_findings_count": len(new_findings),
                "added": len(added),
                "removed": len(removed),
                "unchanged": len(unchanged),
                "severity_changes": len(severity_changes),
            },
            "added_findings": added,
            "removed_findings": removed,
            "severity_changes": severity_changes,
        }

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)

        return result

    @classmethod
    def _create_finding_map(cls, findings: List[Dict]) -> Dict[str, Dict]:
        """Create a map of findings keyed by title"""
        return {f.get("title", ""): f for f in findings if f.get("title")}

    @classmethod
    def generate_comparison_report(
        cls, comparison_result: Dict[str, Any], output_path: Path
    ) -> None:
        """Generate a human-readable comparison report"""
        lines = [
            "# 📊 Security Analysis Version Comparison Report",
            "",
            f"**Comparison Date:** {comparison_result['comparison_date']}",
            "",
            "## 📈 Summary",
            "",
            f"- **Old Findings:** {comparison_result['summary']['old_findings_count']}",
            f"- **New Findings:** {comparison_result['summary']['new_findings_count']}",
            f"- **✅ Fixed (Removed):** {comparison_result['summary']['removed']}",
            f"- **⚠️ New (Added):** {comparison_result['summary']['added']}",
            f"- **🔄 Severity Changes:** {comparison_result['summary']['severity_changes']}",
            "",
            "---",
            "",
        ]

        if comparison_result["removed_findings"]:
            lines.extend(["## ✅ Fixed Issues (Removed)", ""])
            for finding in comparison_result["removed_findings"]:
                lines.append(
                    f"- {finding.get('title', 'Unknown')} (Severity: {finding.get('severity', 'INFO')})"
                )
            lines.append("")

        if comparison_result["added_findings"]:
            lines.extend(["## ⚠️ New Issues (Added)", ""])
            for finding in comparison_result["added_findings"]:
                lines.append(
                    f"- {finding.get('title', 'Unknown')} (Severity: {finding.get('severity', 'INFO')})"
                )
            lines.append("")

        if comparison_result["severity_changes"]:
            lines.extend(["## 🔄 Severity Changes", ""])
            for change in comparison_result["severity_changes"]:
                lines.append(
                    f"- {change['title']}: {change['old_severity']} → {change['new_severity']}"
                )
            lines.append("")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
