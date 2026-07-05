import base64
import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import matplotlib
import matplotlib.pyplot as plt

matplotlib.use("Agg")


class ReportGenerator:
    def __init__(self):
        self.vazir_font_url = "https://cdn.jsdelivr.net/gh/rastikerdar/vazir-font@v30.1.0/dist/font-face.css"

    def generate_html_report(
        self,
        results: Dict[str, Any],
        apk_name: str = "Unknown",
        language: str = "en",
        output_path: Optional[str] = None,
    ) -> str:

        if language == "fa":
            return self._generate_persian_html(results, apk_name, output_path)
        else:
            return self._generate_english_html(results, apk_name, output_path)

    def _generate_persian_html(
        self, results: Dict[str, Any], apk_name: str, output_path: Optional[str]
    ) -> str:
        vulns = results.get("vulnerabilities", [])
        stats = self._calculate_stats(vulns)
        chart_base64 = self._create_pie_chart(stats)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f'''<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>گزارش امنیتی reAVS - {apk_name}</title>
    <link href="{self.vazir_font_url}" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Vazir', Tahoma, sans-serif;
        }}

        body {{
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            color: #e0e0e0;
            padding: 20px;
            direction: rtl;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(26, 31, 58, 0.95);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 0 30px rgba(0, 255, 65, 0.2);
            border: 2px solid #00ff41;
        }}

        .header {{
            text-align: center;
            padding: 20px;
            border-bottom: 2px solid #00ff41;
            margin-bottom: 30px;
        }}

        .logo {{
            font-size: 48px;
            margin-bottom: 10px;
        }}

        h1 {{
            color: #00ff41;
            font-size: 32px;
            margin-bottom: 10px;
            text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
        }}

        h2 {{
            color: #00d4ff;
            font-size: 24px;
            margin: 20px 0 15px 0;
            border-right: 4px solid #00d4ff;
            padding-right: 10px;
        }}

        .info-box {{
            background: rgba(10, 14, 39, 0.8);
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            border: 1px solid #00d4ff;
        }}

        .info-row {{
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px solid rgba(0, 212, 255, 0.2);
        }}

        .info-label {{
            color: #00d4ff;
            font-weight: bold;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}

        .stat-card {{
            background: rgba(10, 14, 39, 0.8);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 2px solid;
            transition: transform 0.3s;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
        }}

        .stat-critical {{ border-color: #ff0055; color: #ff0055; }}
        .stat-high {{ border-color: #ff6600; color: #ff6600; }}
        .stat-medium {{ border-color: #ffcc00; color: #ffcc00; }}
        .stat-low {{ border-color: #00ff41; color: #00ff41; }}

        .stat-number {{
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }}

        .stat-label {{
            font-size: 16px;
            opacity: 0.9;
        }}

        .chart-container {{
            text-align: center;
            margin: 30px 0;
            background: rgba(10, 14, 39, 0.8);
            padding: 20px;
            border-radius: 10px;
        }}

        .vuln-list {{
            margin: 20px 0;
        }}

        .vuln-item {{
            background: rgba(10, 14, 39, 0.8);
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            border-right: 4px solid;
        }}

        .vuln-critical {{ border-right-color: #ff0055; }}
        .vuln-high {{ border-right-color: #ff6600; }}
        .vuln-medium {{ border-right-color: #ffcc00; }}
        .vuln-low {{ border-right-color: #00ff41; }}

        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}

        .vuln-title {{
            font-size: 18px;
            font-weight: bold;
            color: #00d4ff;
        }}

        .vuln-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }}

        .badge-critical {{ background: #ff0055; color: white; }}
        .badge-high {{ background: #ff6600; color: white; }}
        .badge-medium {{ background: #ffcc00; color: black; }}
        .badge-low {{ background: #00ff41; color: black; }}

        .vuln-details {{
            margin-top: 10px;
            line-height: 1.8;
        }}

        .detail-row {{
            padding: 5px 0;
        }}

        .detail-label {{
            color: #00ff41;
            font-weight: bold;
            margin-left: 10px;
        }}

        .code-flow {{
            background: #0a0e27;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            direction: ltr;
            text-align: left;
            overflow-x: auto;
        }}

        .flow-arrow {{
            color: #00ff41;
            margin: 0 10px;
        }}

        .footer {{
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 2px solid #00ff41;
            color: #00ff41;
        }}

        @media print {{
            body {{ background: white; }}
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️</div>
            <h1>گزارش تحلیل امنیتی reAVS</h1>
            <p style="color: #00d4ff; font-size: 18px;">ابزار تحلیل ایستای بدافزار اندروید</p>
        </div>

        <div class="info-box">
            <h2>📱 اطلاعات فایل</h2>
            <div class="info-row">
                <span class="info-label">نام فایل:</span>
                <span>{apk_name}</span>
            </div>
            <div class="info-row">
                <span class="info-label">تاریخ اسکن:</span>
                <span>{timestamp}</span>
            </div>
            <div class="info-row">
                <span class="info-label">حالت اسکن:</span>
                <span>{results.get("scan_mode", "fast").upper()}</span>
            </div>
            <div class="info-row">
                <span class="info-label">عمق تحلیل:</span>
                <span>{results.get("depth", "N/A")}</span>
            </div>
        </div>

        <h2>📊 آمار آسیب‌پذیری‌ها</h2>
        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <div class="stat-label">بحرانی</div>
                <div class="stat-number">{stats["CRITICAL"]}</div>
            </div>
            <div class="stat-card stat-high">
                <div class="stat-label">بالا</div>
                <div class="stat-number">{stats["HIGH"]}</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="stat-label">متوسط</div>
                <div class="stat-number">{stats["MEDIUM"]}</div>
            </div>
            <div class="stat-card stat-low">
                <div class="stat-label">پایین</div>
                <div class="stat-number">{stats["LOW"]}</div>
            </div>
        </div>

        <div class="chart-container">
            <h2>📈 نمودار توزیع آسیب‌پذیری‌ها</h2>
            <img src="data:image/png;base64,{chart_base64}" alt="Chart" style="max-width: 100%;">
        </div>

        <h2>🔍 جزئیات آسیب‌پذیری‌ها ({len(vulns)} مورد)</h2>
        <div class="vuln-list">
'''

        for i, vuln in enumerate(vulns, 1):
            severity = vuln.get("severity", "LOW").upper()
            severity_fa = {
                "CRITICAL": "بحرانی",
                "HIGH": "بالا",
                "MEDIUM": "متوسط",
                "LOW": "پایین",
            }.get(severity, "نامشخص")

            html += f"""
            <div class="vuln-item vuln-{severity.lower()}">
                <div class="vuln-header">
                    <span class="vuln-title">#{i} - {vuln.get("type", "نامشخص")}</span>
                    <span class="vuln-badge badge-{severity.lower()}">{severity_fa}</span>
                </div>
                <div class="vuln-details">
                    <div class="detail-row">
                        <span class="detail-label">موقعیت:</span>
                        <span>{vuln.get("location", "N/A")}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">توضیحات:</span>
                        <span>{vuln.get("description", "N/A")}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">ریسک:</span>
                        <span>{vuln.get("risk", "N/A")}</span>
                    </div>
"""

            if "code_flow" in vuln and vuln["code_flow"]:
                html += """
                    <div class="detail-row">
                        <span class="detail-label">مسیر کد:</span>
                        <div class="code-flow">
"""
                for j, step in enumerate(vuln["code_flow"]):
                    html += f"                            {step}"
                    if j < len(vuln["code_flow"]) - 1:
                        html += ' <span class="flow-arrow">→</span>\n'
                    else:
                        html += "\n"

                html += """
                        </div>
                    </div>
"""

            html += """
                </div>
            </div>
"""

        html += f"""
        </div>

        <div class="footer">
            <p>🛡️ تولید شده توسط reAVS Pro GUI</p>
            <p>تاریخ: {timestamp}</p>
        </div>
    </div>
</body>
</html>"""

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

        return html

    def _generate_english_html(
        self, results: Dict[str, Any], apk_name: str, output_path: Optional[str]
    ) -> str:
        vulns = results.get("vulnerabilities", [])
        stats = self._calculate_stats(vulns)
        chart_base64 = self._create_pie_chart(stats)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>reAVS Security Report - {apk_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #0a0e27; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #1a1f3a; padding: 30px; border-radius: 10px; }}
        h1 {{ color: #00ff41; text-align: center; }}
        h2 {{ color: #00d4ff; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .stat {{ padding: 20px; border-radius: 8px; text-align: center; }}
        .critical {{ background: #ff0055; }}
        .high {{ background: #ff6600; }}
        .medium {{ background: #ffcc00; color: black; }}
        .low {{ background: #00ff41; color: black; }}
        .vuln {{ background: #0a0e27; padding: 15px; margin: 10px 0; border-radius: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ reAVS Security Report</h1>
        <p style="text-align: center;">APK: {apk_name} | Date: {timestamp}</p>

        <h2>Vulnerability Statistics</h2>
        <div class="stats">
            <div class="stat critical"><h3>Critical</h3><p style="font-size: 36px;">{stats["CRITICAL"]}</p></div>
            <div class="stat high"><h3>High</h3><p style="font-size: 36px;">{stats["HIGH"]}</p></div>
            <div class="stat medium"><h3>Medium</h3><p style="font-size: 36px;">{stats["MEDIUM"]}</p></div>
            <div class="stat low"><h3>Low</h3><p style="font-size: 36px;">{stats["LOW"]}</p></div>
        </div>

        <div style="text-align: center; margin: 30px 0;">
            <img src="data:image/png;base64,{chart_base64}" alt="Chart">
        </div>

        <h2>Vulnerability Details ({len(vulns)})</h2>
"""

        for i, vuln in enumerate(vulns, 1):
            severity = vuln.get("severity", "LOW").upper()
            html += f"""
        <div class="vuln">
            <h3>#{i} - {vuln.get("type", "Unknown")} [{severity}]</h3>
            <p><strong>Location:</strong> {vuln.get("location", "N/A")}</p>
            <p><strong>Description:</strong> {vuln.get("description", "N/A")}</p>
            <p><strong>Risk:</strong> {vuln.get("risk", "N/A")}</p>
        </div>
"""

        html += """
    </div>
</body>
</html>"""

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html)

        return html

    def _calculate_stats(self, vulns: List[Dict[str, Any]]) -> Dict[str, int]:
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulns:
            severity = vuln.get("severity", "LOW").upper()
            if severity in stats:
                stats[severity] += 1
        return stats

    def _create_pie_chart(self, stats: Dict[str, int]) -> str:
        labels = ["Critical", "High", "Medium", "Low"]
        sizes = [stats["CRITICAL"], stats["HIGH"], stats["MEDIUM"], stats["LOW"]]
        colors = ["#ff0055", "#ff6600", "#ffcc00", "#00ff41"]

        fig, ax = plt.subplots(figsize=(8, 6))
        fig.patch.set_facecolor("#0a0e27")
        ax.set_facecolor("#1a1f3a")

        if sum(sizes) > 0:
            wedges, texts, autotexts = ax.pie(
                sizes,
                labels=labels,
                colors=colors,
                autopct="%1.1f%%",
                startangle=90,
                textprops={"color": "white", "fontsize": 12},
            )
            for autotext in autotexts:
                autotext.set_color("white")
                autotext.set_fontweight("bold")
        else:
            ax.text(
                0.5,
                0.5,
                "No Vulnerabilities",
                horizontalalignment="center",
                verticalalignment="center",
                color="white",
                fontsize=16,
            )

        from io import BytesIO

        buf = BytesIO()
        plt.savefig(
            buf,
            format="png",
            facecolor=fig.get_facecolor(),
            bbox_inches="tight",
            dpi=100,
        )
        buf.seek(0)
        img_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        plt.close(fig)

        return img_base64

    def generate_sarif(self, results: Dict[str, Any], output_path: str):
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "reAVS",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/aimardcr/reAVS",
                        }
                    },
                    "results": [],
                }
            ],
        }

        for vuln in results.get("vulnerabilities", []):
            severity = vuln.get("severity", "LOW").upper()
            level = {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note",
            }.get(severity, "note")

            result = {
                "ruleId": vuln.get("type", "unknown"),
                "level": level,
                "message": {"text": vuln.get("description", "No description")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": vuln.get("location", "unknown")}
                        }
                    }
                ],
            }
            sarif["runs"][0]["results"].append(result)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)

    def generate_csv(self, results: Dict[str, Any], output_path: str):
        import pandas as pd

        vulns = results.get("vulnerabilities", [])
        df = pd.DataFrame(vulns)

        if df.empty:
            df = pd.DataFrame(
                columns=["type", "severity", "location", "description", "risk"]
            )

        df.to_csv(output_path, index=False, encoding="utf-8")

    def generate_pdf(self, results: Dict[str, Any], apk_name: str, output_path: str):
        html_content = self._generate_english_html(results, apk_name, None)

        try:
            from weasyprint import HTML

            HTML(string=html_content).write_pdf(output_path)
        except ImportError:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table

            doc = SimpleDocTemplate(output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []

            title_style = ParagraphStyle(
                "CustomTitle",
                parent=styles["Heading1"],
                fontSize=24,
                textColor=colors.HexColor("#00ff41"),
                spaceAfter=30,
            )

            story.append(Paragraph(f"reAVS Security Report - {apk_name}", title_style))
            story.append(Spacer(1, 20))

            vulns = results.get("vulnerabilities", [])
            stats = self._calculate_stats(vulns)

            story.append(Paragraph("Vulnerability Statistics", styles["Heading2"]))
            story.append(Spacer(1, 10))

            data = [
                ["Severity", "Count"],
                ["Critical", str(stats["CRITICAL"])],
                ["High", str(stats["HIGH"])],
                ["Medium", str(stats["MEDIUM"])],
                ["Low", str(stats["LOW"])],
            ]

            table = Table(data)
            table.setStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00ff41")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
            story.append(table)
            story.append(Spacer(1, 20))

            story.append(
                Paragraph(f"Vulnerability Details ({len(vulns)})", styles["Heading2"])
            )
            story.append(Spacer(1, 10))

            for i, vuln in enumerate(vulns[:50], 1):
                severity = vuln.get("severity", "LOW").upper()
                story.append(
                    Paragraph(
                        f"<b>#{i} - {vuln.get('type', 'Unknown')} [{severity}]</b>",
                        styles["Heading3"],
                    )
                )
                story.append(
                    Paragraph(
                        f"Location: {vuln.get('location', 'N/A')}", styles["Normal"]
                    )
                )
                story.append(
                    Paragraph(
                        f"Description: {vuln.get('description', 'N/A')}",
                        styles["Normal"],
                    )
                )
                story.append(Spacer(1, 10))

            doc.build(story)
