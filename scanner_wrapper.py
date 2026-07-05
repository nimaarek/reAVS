import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


class ScannerWrapper:
    def __init__(self, progress_callback: Optional[Callable] = None):
        self.reavs_module = None
        self.use_direct_import = False
        self.project_root = self._find_project_root()
        self.progress_callback = progress_callback
        self._try_direct_import()

    def set_progress_callback(self, callback: Callable):
        self.progress_callback = callback

    def _report_progress(self, stage: str, progress: float, message: str):
        if self.progress_callback:
            try:
                self.progress_callback(stage, progress, message)
            except Exception as e:
                print(f"[!] Progress callback error: {e}")

    def _find_project_root(self):
        possible_paths = [
            os.getcwd(),
            os.path.dirname(os.path.dirname(__file__)),
            os.path.dirname(__file__),
        ]

        for path in possible_paths:
            avs_path = os.path.join(path, "avs.py")
            if os.path.exists(avs_path):
                print(f"[+] Found reAVS project at: {path}")
                return path

        print("[!] reAVS project not found, using current directory")
        return os.getcwd()

    def _try_direct_import(self):
        try:
            if self.project_root and self.project_root not in sys.path:
                sys.path.insert(0, self.project_root)

            from core.cli import main

            self.reavs_module = main
            self.use_direct_import = True
            print("[+] Successfully imported reAVS core.cli module")
        except Exception as e:
            print(f"[!] Direct import failed: {e}")
            print("[!] Falling back to subprocess mode")
            self.use_direct_import = False

    def normalize_results(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        """Convert avs.py output format to our standard format"""

        normalized = {
            "status": "success",
            "vulnerabilities": [],
            "summary": {},
            "components": {},
            "methods": {},
            "app_info": {},
            "raw_data": raw_results,
        }

        # Extract app info
        if "app" in raw_results:
            normalized["app_info"] = raw_results["app"]

        # Extract summary
        if "summary" in raw_results:
            normalized["summary"] = raw_results["summary"]
            if "findings_by_severity" in raw_results["summary"]:
                normalized["summary"]["severity_counts"] = raw_results["summary"][
                    "findings_by_severity"
                ]

        # Extract attack surface info
        if "attack_surface" in raw_results:
            attack_surface = raw_results["attack_surface"]
            normalized["components"] = {
                "activities": len(attack_surface.get("activities", [])),
                "services": len(attack_surface.get("services", [])),
                "receivers": len(attack_surface.get("receivers", [])),
                "providers": len(attack_surface.get("providers", [])),
            }

        # Process findings
        findings = raw_results.get("findings", [])

        if isinstance(findings, list):
            for finding in findings:
                # Extract location from entrypoint_method or primary_method
                location = finding.get(
                    "entrypoint_method",
                    finding.get("primary_method", finding.get("sink_method", "N/A")),
                )

                # Extract component from component_name, component_desc, or class_name
                component = finding.get(
                    "component_name",
                    finding.get("component_desc", finding.get("class_name", "N/A")),
                )

                if not component or component is None:
                    component = "N/A"

                # Extract risk from recommendation or confidence
                risk = finding.get("recommendation", "N/A")
                if risk == "N/A" or not risk:
                    confidence = finding.get("confidence", "UNKNOWN")
                    severity = finding.get("severity", "MEDIUM").upper()
                    risk = f"Confidence: {confidence}, Severity: {severity}"

                # Extract code flow from evidence
                code_flow = []
                evidence = finding.get("evidence", [])
                if isinstance(evidence, list):
                    for ev in evidence:
                        if isinstance(ev, dict):
                            kind = ev.get("kind", "")
                            method = ev.get("method", "")
                            desc = ev.get("description", "")
                            if method:
                                code_flow.append(f"{kind}: {method} - {desc}")

                # Extract references (CWE)
                references = finding.get("references", [])

                vuln = {
                    "type": finding.get("id", finding.get("title", "UNKNOWN")),
                    "title": finding.get("title", ""),
                    "severity": finding.get("severity", "MEDIUM").upper(),
                    "confidence": finding.get("confidence", "UNKNOWN"),
                    "location": location,
                    "component": component,
                    "component_exported": finding.get("component_exported", False),
                    "description": finding.get(
                        "description", "No description available"
                    ),
                    "risk": risk,
                    "recommendation": finding.get("recommendation", ""),
                    "code_flow": code_flow,
                    "evidence": evidence,
                    "references": references,
                    "fingerprint": finding.get("fingerprint", ""),
                    "details": {
                        "severity_basis": finding.get("severity_basis", ""),
                        "confidence_basis": finding.get("confidence_basis", ""),
                        "entrypoint_method": finding.get("entrypoint_method", ""),
                        "primary_method": finding.get("primary_method", ""),
                        "sink_method": finding.get("sink_method", ""),
                        "related_methods": finding.get("related_methods", []),
                    },
                }
                normalized["vulnerabilities"].append(vuln)

        return normalized

    def scan(
        self,
        apk_path: str,
        mode: str = "fast",
        depth: int = 10,
        output_file: Optional[str] = None,
    ) -> Dict[str, Any]:

        self._report_progress("start", 0.0, "Initializing scan...")

        if self.use_direct_import:
            return self._scan_direct(apk_path, mode, depth, output_file)
        else:
            return self._scan_subprocess(apk_path, mode, depth, output_file)

    def _scan_direct(
        self, apk_path: str, mode: str, depth: int, output_file: Optional[str]
    ) -> Dict[str, Any]:
        try:
            self._report_progress("preparing", 0.1, "Preparing analysis environment...")

            if not output_file:
                temp_file = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                )
                output_file = temp_file.name
                temp_file.close()

            args = [apk_path]

            if mode == "deep":
                args.append("--deep")
                args.extend(["--depth", str(depth)])

            args.extend(["--out", output_file])

            self._report_progress(
                "analyzing", 0.2, f"Starting analysis: {os.path.basename(apk_path)}"
            )

            exit_code = self.reavs_module(args)

            if exit_code == 0 and os.path.exists(output_file):
                self._report_progress("processing", 0.9, "Reading scan results...")

                with open(output_file, "r", encoding="utf-8") as f:
                    raw_results = json.load(f)

                self._report_progress("normalizing", 0.95, "Processing findings...")
                results = self.normalize_results(raw_results)

                vuln_count = len(results.get("vulnerabilities", []))
                self._report_progress(
                    "complete",
                    1.0,
                    f"✅ Scan complete! Found {vuln_count} vulnerabilities",
                )

                return results
            else:
                return {
                    "status": "error",
                    "error": f"Scan failed with exit code {exit_code}",
                    "vulnerabilities": [],
                }

        except Exception as e:
            import traceback

            traceback.print_exc()
            return {"status": "error", "error": str(e), "vulnerabilities": []}

    def _scan_subprocess(
        self, apk_path: str, mode: str, depth: int, output_file: Optional[str]
    ) -> Dict[str, Any]:
        try:
            self._report_progress(
                "preparing", 0.05, "Preparing analysis environment..."
            )

            if not output_file:
                temp_file = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".json", delete=False
                )
                output_file = temp_file.name
                temp_file.close()

            avs_script = os.path.join(self.project_root, "avs.py")

            if not os.path.exists(avs_script):
                return {
                    "status": "error",
                    "error": f"avs.py not found at {avs_script}",
                    "vulnerabilities": [],
                }

            cmd = [sys.executable, avs_script, apk_path]

            if mode == "deep":
                cmd.append("--deep")
                cmd.extend(["--depth", str(depth)])

            cmd.extend(["--out", output_file])

            self._report_progress(
                "starting", 0.1, f"Launching scanner: {os.path.basename(apk_path)}"
            )

            # Use Popen for real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=self.project_root,
                universal_newlines=True,
            )

            # Parse output in real-time
            progress = 0.1
            scanner_count = 0
            total_scanners = 10  # Estimated

            for line in process.stdout:
                line = line.strip()
                if not line:
                    continue

                # Print to console for debugging
                print(f"[AVS] {line}")

                # Parse progress indicators
                if "scanner start name=" in line:
                    match = re.search(r"name=(\w+)", line)
                    if match:
                        scanner_name = match.group(1)
                        scanner_count += 1
                        progress = 0.2 + (scanner_count / total_scanners) * 0.5
                        self._report_progress(
                            "analyzing", progress, f"🔍 Scanning: {scanner_name}"
                        )

                elif "scanner end name=" in line:
                    match = re.search(r"name=(\w+).*findings=(\d+)", line)
                    if match:
                        scanner_name = match.group(1)
                        findings = int(match.group(2))
                        self._report_progress(
                            "analyzing",
                            progress,
                            f"✓ {scanner_name}: {findings} findings",
                        )

                elif "components" in line and "activities=" in line:
                    self._report_progress(
                        "analyzing", 0.75, "📊 Analyzing components..."
                    )

                elif "methods analyzed=" in line:
                    match = re.search(r"analyzed=(\d+)", line)
                    if match:
                        methods = int(match.group(1))
                        self._report_progress(
                            "analyzing", 0.8, f"⚙️ Methods analyzed: {methods}"
                        )

                elif "findings CRITICAL=" in line:
                    self._report_progress(
                        "processing", 0.85, "📝 Compiling findings..."
                    )

                elif "report json=" in line:
                    self._report_progress("processing", 0.9, "💾 Generating report...")

                elif line.startswith("[*]") or line.startswith("[+]"):
                    # Generic progress message
                    msg = line[3:].strip() if len(line) > 3 else line
                    self._report_progress(
                        "analyzing", min(progress + 0.01, 0.89), f"⚡ {msg}"
                    )

            process.wait(timeout=600)

            if process.returncode == 0 and os.path.exists(output_file):
                self._report_progress("processing", 0.95, "Reading scan results...")

                with open(output_file, "r", encoding="utf-8") as f:
                    raw_results = json.load(f)

                self._report_progress("normalizing", 0.98, "Processing findings...")
                results = self.normalize_results(raw_results)

                vuln_count = len(results.get("vulnerabilities", []))
                self._report_progress(
                    "complete",
                    1.0,
                    f"✅ Scan complete! Found {vuln_count} vulnerabilities",
                )

                return results
            else:
                return {
                    "status": "error",
                    "error": f"Exit code: {process.returncode}",
                    "vulnerabilities": [],
                }

        except subprocess.TimeoutExpired:
            process.kill()
            return {"status": "timeout", "vulnerabilities": []}
        except Exception as e:
            import traceback

            traceback.print_exc()
            return {"status": "error", "error": str(e), "vulnerabilities": []}

    def get_available_rules(self) -> List[Dict[str, Any]]:
        rules_dir = os.path.join(self.project_root, "core", "rules")

        if not os.path.exists(rules_dir):
            return []

        rules = []
        try:
            import yaml

            for filename in os.listdir(rules_dir):
                if filename.endswith((".yml", ".yaml")):
                    filepath = os.path.join(rules_dir, filename)
                    with open(filepath, "r", encoding="utf-8") as f:
                        rule_data = yaml.safe_load(f)
                        rule_data["filename"] = filename
                        rules.append(rule_data)
        except Exception as e:
            print(f"[!] Error loading rules: {e}")

        return rules

    def add_rule(self, rule_data: Dict[str, Any]) -> bool:
        rules_dir = os.path.join(self.project_root, "custom_rules")
        if not os.path.exists(rules_dir):
            os.makedirs(rules_dir)

        try:
            import yaml

            filename = f"custom_rule_{int(datetime.now().timestamp())}.yml"
            filepath = os.path.join(rules_dir, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                yaml.dump(rule_data, f, default_flow_style=False, allow_unicode=True)

            return True
        except Exception as e:
            print(f"[!] Error adding rule: {e}")
            return False

    def delete_rule(self, filename: str) -> bool:
        rules_dir = os.path.join(self.project_root, "custom_rules")
        filepath = os.path.join(rules_dir, filename)

        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                return True
            return False
        except Exception as e:
            print(f"[!] Error deleting rule: {e}")
            return False
