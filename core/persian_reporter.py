import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

class PersianReporter:
    """ساخت گزارش فارسی به فرمت Markdown از خروجی JSON reAVS"""

    SEVERITY_FA_PERSIAN = {
        "CRITICAL": "🔴 بحرانی",
        "HIGH": "🟠 بالا",
        "MEDIUM": "🟡 متوسط",
        "LOW": "🟢 پایین",
        "INFO": "ℹ️ اطلاعاتی"
    }

    @classmethod
    def generate_report(cls, json_path: Path, output_path: Path = None) -> Path:
        """
        تولید گزارش فارسی از فایل JSON

        Args:
            json_path: مسیر فایل JSON خروجی reAVS
            output_path: مسیر خروجی دلخواه (اختیاری)

        Returns:
            مسیر فایل Markdown تولید شده
        """
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        if output_path is None:
            output_path = json_path.parent / f"persian_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        md_content = cls._build_markdown(data)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

        return output_path

    @classmethod
    def _build_markdown(cls, data: Dict[str, Any]) -> str:
        """ساخت محتوای Markdown از داده‌های JSON"""

        findings = data.get('findings', [])
        metadata = data.get('metadata', {})

        lines = [
            "# 📱 گزارش تحلیل امنیتی APK",
            "",
            f"**نام فایل:** `{metadata.get('apk_name', 'نامشخص')}`",
            f"**تاریخ تحلیل:** {datetime.now().strftime('%Y/%m/%d %H:%M:%S')}",
            f"**حالت تحلیل:** {metadata.get('scan_mode', 'نامشخص')}",
            f"**تعداد یافته‌ها:** {len(findings)}",
            "",
            "---",
            "",
            "## 📊 خلاصه یافته‌ها بر اساس شدت",
            ""
        ]

        # آمار بر اساس شدت
        severity_count = {}
        for finding in findings:
            sev = finding.get('severity', 'INFO')
            severity_count[sev] = severity_count.get(sev, 0) + 1

        for sev, count in severity_count.items():
            persian_sev = cls.SEVERITY_FA_PERSIAN.get(sev, sev)
            lines.append(f"- **{persian_sev}**: {count} مورد")

        lines.extend([
            "",
            "---",
            "",
            "## 🔍 جزئیات کامل یافته‌ها",
            ""
        ])

        # نمایش جزئیات هر یافته
        for idx, finding in enumerate(findings, 1):
            lines.extend(cls._format_finding(idx, finding))
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def _format_finding(cls, index: int, finding: Dict[str, Any]) -> List[str]:
        """فرمت‌بندی یک یافته به صورت Markdown"""

        title = finding.get('title', 'یافته بدون عنوان')
        severity = finding.get('severity', 'INFO')
        persian_sev = cls.SEVERITY_FA_PERSIAN.get(severity, severity)
        description = finding.get('description', 'توضیحاتی موجود نیست')
        location = finding.get('location', 'نامشخص')
        recommendation = finding.get('recommendation', 'توصیه‌ای ثبت نشده است')
        cwe = finding.get('cwe', '')

        lines = [
            f"### {index}. {title}",
            "",
            f"- **شدت خطر:** {persian_sev}",
            f"- **مکان:** `{location}`",
        ]

        if cwe:
            lines.append(f"- **CWE:** `{cwe}`")

        lines.extend([
            "",
            f"**توضیح:**",
            f"> {description}",
            "",
            f"**توصیه:**",
            f"> {recommendation}",
            "",
            "---",
            ""
        ])

        return lines
