import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List  # Add this import


class HTMLReporter:
    """Generates interactive HTML reports from reAVS JSON output"""

    @classmethod
    def generate_report(cls, json_path: Path, output_path: Path = None) -> Path:
        """Generate interactive HTML report"""
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if output_path is None:
            output_path = (
                json_path.parent
                / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            )

        html_content = cls._build_html(data)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_path

    @classmethod
    def _build_html(cls, data: Dict[str, Any]) -> str:
        """Build complete HTML page"""
        findings = data.get("findings", [])
        metadata = data.get("metadata", {})

        # Calculate statistics
        severity_counts = {}
        for finding in findings:
            sev = finding.get("severity", "INFO")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Build findings HTML
        findings_html = cls._build_findings_html(findings)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>reAVS Security Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0e17;
            color: #e0e7f0;
            line-height: 1.6;
            padding: 20px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1a2332 0%, #2a3f5a 100%);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .header h1 {{ color: #60a5fa; font-size: 2em; margin-bottom: 10px; }}
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .metadata-item {{
            background: rgba(255,255,255,0.05);
            padding: 10px 15px;
            border-radius: 8px;
            border-left: 3px solid #60a5fa;
        }}
        .metadata-item .label {{ color: #94a3b8; font-size: 0.8em; }}
        .metadata-item .value {{ font-weight: bold; font-size: 1.1em; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #1a2332;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #2a3f5a;
        }}
        .stat-card .number {{ font-size: 2em; font-weight: bold; }}
        .stat-card .label {{ color: #94a3b8; font-size: 0.9em; }}
        .severity-critical .number {{ color: #ef4444; }}
        .severity-high .number {{ color: #f59e0b; }}
        .severity-medium .number {{ color: #eab308; }}
        .severity-low .number {{ color: #22c55e; }}
        .severity-info .number {{ color: #3b82f6; }}
        .finding {{
            background: #1a2332;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid #60a5fa;
        }}
        .finding.critical {{ border-left-color: #ef4444; }}
        .finding.high {{ border-left-color: #f59e0b; }}
        .finding.medium {{ border-left-color: #eab308; }}
        .finding.low {{ border-left-color: #22c55e; }}
        .finding.info {{ border-left-color: #3b82f6; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{ font-size: 1.1em; font-weight: bold; }}
        .finding-severity {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .finding-severity.critical {{ background: #ef4444; color: white; }}
        .finding-severity.high {{ background: #f59e0b; color: white; }}
        .finding-severity.medium {{ background: #eab308; color: white; }}
        .finding-severity.low {{ background: #22c55e; color: white; }}
        .finding-severity.info {{ background: #3b82f6; color: white; }}
        .finding-details {{
            margin-top: 10px;
            padding: 10px;
            background: rgba(255,255,255,0.05);
            border-radius: 4px;
        }}
        .finding-details strong {{ color: #94a3b8; }}
        .finding-location {{
            font-family: 'Courier New', monospace;
            background: #0d1520;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .finding-evidence {{
            margin-top: 8px;
            padding-left: 20px;
            color: #94a3b8;
            font-size: 0.9em;
        }}
        .finding-evidence li {{ margin-bottom: 4px; }}
        .scanner-tag {{
            display: inline-block;
            background: #2a3f5a;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            color: #94a3b8;
            margin-left: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 reAVS Security Analysis Report</h1>
            <div class="metadata">
                <div class="metadata-item">
                    <div class="label">APK Name</div>
                    <div class="value">{metadata.get("apk_name", "Unknown")}</div>
                </div>
                <div class="metadata-item">
                    <div class="label">Analysis Date</div>
                    <div class="value">{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
                </div>
                <div class="metadata-item">
                    <div class="label">Scan Mode</div>
                    <div class="value">{metadata.get("scan_mode", "Unknown")}</div>
                </div>
                <div class="metadata-item">
                    <div class="label">Total Findings</div>
                    <div class="value">{len(findings)}</div>
                </div>
            </div>
        </div>

        <div class="stats">
            <div class="stat-card severity-critical">
                <div class="number">{severity_counts.get("CRITICAL", 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card severity-high">
                <div class="number">{severity_counts.get("HIGH", 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card severity-medium">
                <div class="number">{severity_counts.get("MEDIUM", 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card severity-low">
                <div class="number">{severity_counts.get("LOW", 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card severity-info">
                <div class="number">{severity_counts.get("INFO", 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <h2 style="margin-bottom: 20px;">Detailed Findings</h2>
        {findings_html}
    </div>
</body>
</html>"""

    @classmethod
    def _build_findings_html(cls, findings: List[Dict]) -> str:
        """Build HTML for findings section"""
        html = []
        for finding in findings:
            severity = finding.get("severity", "INFO").lower()
            title = finding.get("title", "Untitled Finding")
            description = finding.get("description", "No description")
            location = finding.get("location", "Unknown")
            recommendation = finding.get("recommendation", "No recommendation")
            cwe = finding.get("cwe", "")
            evidence = finding.get("evidence", [])
            scanner = finding.get("scanner", "Unknown")

            html.append(f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">
                        {title}
                        <span class="scanner-tag">📎 {scanner}</span>
                    </div>
                    <span class="finding-severity {severity}">{severity.upper()}</span>
                </div>
                <div class="finding-details">
                    <p><strong>Location:</strong> <span class="finding-location">{
                location
            }</span></p>
                    {f"<p><strong>CWE:</strong> {cwe}</p>" if cwe else ""}
                    <p><strong>Description:</strong></p>
                    <p>{description}</p>
                    <p><strong>Recommendation:</strong></p>
                    <p>{recommendation}</p>
                    {
                f'''
                    <p><strong>Evidence:</strong></p>
                    <ul class="finding-evidence">
                        {"".join(f'<li>{e}</li>' for e in evidence)}
                    </ul>
                    '''
                if evidence
                else ""
            }
                </div>
            </div>
            """)

        return "\n".join(html)
