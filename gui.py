import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.persian_reporter import PersianReporter
from core_improvements.html_reporter import HTMLReporter
from core_improvements.version_comparator import VersionComparator

# ... rest of the gui.py code remains the same ...


class ReAVSGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("reAVS - Android Security Analyzer")
        self.geometry("900x700")
        self.minsize(800, 600)

        # Variables
        self.apk_path = None
        self.json_report_path = None
        self.persian_report_path = None
        self.html_report_path = None
        self.analysis_thread = None
        self.compare_mode = False
        self.old_report_path = None
        self.new_report_path = None

        self._create_widgets()

    def _create_widgets(self):
        """Create all GUI widgets"""

        # ===== Top Frame (File Selection) =====
        self.top_frame = ctk.CTkFrame(self)
        self.top_frame.pack(pady=10, padx=20, fill="x")

        self.file_label = ctk.CTkLabel(
            self.top_frame, text="No file selected", font=("Segoe UI", 12)
        )
        self.file_label.pack(side="left", padx=10)

        self.select_btn = ctk.CTkButton(
            self.top_frame, text="📂 Select APK", command=self.select_apk, width=120
        )
        self.select_btn.pack(side="right", padx=10)

        # ===== Middle Frame (Controls) =====
        self.mid_frame = ctk.CTkFrame(self)
        self.mid_frame.pack(pady=10, padx=20, fill="x")

        # Mode selection
        self.mode_frame = ctk.CTkFrame(self.mid_frame)
        self.mode_frame.pack(pady=5, fill="x")

        self.analyze_mode = ctk.CTkButton(
            self.mode_frame,
            text="🔍 Analysis Mode",
            command=self.set_analysis_mode,
            width=120,
        )
        self.analyze_mode.pack(side="left", padx=5)

        self.compare_mode_btn = ctk.CTkButton(
            self.mode_frame,
            text="📊 Compare Mode",
            command=self.set_compare_mode,
            width=120,
        )
        self.compare_mode_btn.pack(side="left", padx=5)

        self.report_options_frame = ctk.CTkFrame(self.mid_frame)
        self.report_options_frame.pack(pady=5, fill="x")

        self.html_report_check = ctk.CTkCheckBox(
            self.report_options_frame,
            text="Generate HTML Report",
            onvalue=True,
            offvalue=False,
            command=self.toggle_html_report,
        )
        self.html_report_check.pack(side="left", padx=10)
        self.html_report_check.select()

        self.persian_check = ctk.CTkCheckBox(
            self.report_options_frame,
            text="Generate Persian Report",
            onvalue=True,
            offvalue=False,
            command=self.toggle_persian_report,
        )
        self.persian_check.pack(side="left", padx=10)
        self.persian_check.select()

        # Analyze button
        self.analyze_btn = ctk.CTkButton(
            self.mid_frame,
            text="🔍 Start Analysis",
            command=self.start_analysis,
            state="disabled",
            height=40,
            font=("Segoe UI", 14, "bold"),
        )
        self.analyze_btn.pack(pady=5)

        # Progress bar
        self.progressbar = ctk.CTkProgressBar(self.mid_frame)
        self.progressbar.pack(pady=5, fill="x")
        self.progressbar.set(0)

        # Status label
        self.status_label = ctk.CTkLabel(
            self.mid_frame,
            text="⏳ Waiting for file selection...",
            font=("Segoe UI", 11),
        )
        self.status_label.pack(pady=5)

        # ===== Bottom Frame (Output Display) =====
        self.bottom_frame = ctk.CTkFrame(self)
        self.bottom_frame.pack(pady=10, padx=20, fill="both", expand=True)

        # Tabs
        self.tabview = ctk.CTkTabview(self.bottom_frame)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        # JSON Output tab
        self.tab_json = self.tabview.add("📄 JSON Output")
        self.json_textbox = ctk.CTkTextbox(self.tab_json, wrap="none")
        self.json_textbox.pack(fill="both", expand=True)

        # Persian Report tab
        self.tab_persian = self.tabview.add("🇮🇷 Persian Report")
        self.persian_textbox = ctk.CTkTextbox(self.tab_persian, wrap="word")
        self.persian_textbox.pack(fill="both", expand=True)

        # HTML Report preview tab (optional)
        self.tab_html = self.tabview.add("🌐 HTML Report")
        self.html_textbox = ctk.CTkTextbox(self.tab_html, wrap="word")
        self.html_textbox.pack(fill="both", expand=True)

        # Comparison tab
        self.tab_compare = self.tabview.add("📊 Version Compare")
        self.compare_textbox = ctk.CTkTextbox(self.tab_compare, wrap="word")
        self.compare_textbox.pack(fill="both", expand=True)

        # ===== Bottom Buttons =====
        self.btn_frame = ctk.CTkFrame(self)
        self.btn_frame.pack(pady=10, padx=20, fill="x")

        self.save_json_btn = ctk.CTkButton(
            self.btn_frame,
            text="💾 Save JSON",
            command=self.save_json,
            state="disabled",
            width=120,
        )
        self.save_json_btn.pack(side="left", padx=5)

        self.save_md_btn = ctk.CTkButton(
            self.btn_frame,
            text="📝 Save Persian Report",
            command=self.save_persian_report,
            state="disabled",
            width=150,
        )
        self.save_md_btn.pack(side="left", padx=5)

        self.save_html_btn = ctk.CTkButton(
            self.btn_frame,
            text="🌐 Save HTML Report",
            command=self.save_html_report,
            state="disabled",
            width=150,
        )
        self.save_html_btn.pack(side="left", padx=5)

        self.clear_btn = ctk.CTkButton(
            self.btn_frame, text="🗑️ Clear Output", command=self.clear_output, width=120
        )
        self.clear_btn.pack(side="right", padx=5)

    def select_apk(self):
        """Select APK file via file dialog"""
        file_path = filedialog.askopenfilename(
            title="Select APK File",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")],
        )

        if file_path:
            self.apk_path = Path(file_path)
            self.file_label.configure(text=f"✅ {self.apk_path.name}")
            self.analyze_btn.configure(state="normal")
            self.status_label.configure(text="✅ File selected. Ready for analysis.")

    def set_analysis_mode(self):
        """Set to analysis mode"""
        self.compare_mode = False
        self.analyze_mode.configure(fg_color="#1f538d")
        self.compare_mode_btn.configure(fg_color="gray")
        self.status_label.configure(text="📝 Analysis mode: Single APK analysis")

    def set_compare_mode(self):
        """Set to comparison mode"""
        self.compare_mode = True
        self.compare_mode_btn.configure(fg_color="#1f538d")
        self.analyze_mode.configure(fg_color="gray")
        self.status_label.configure(
            text="📊 Compare mode: Select two reports to compare"
        )

        # Ask for old and new reports
        self._select_reports_for_comparison()

    def _select_reports_for_comparison(self):
        """Select two reports for comparison"""
        old_file = filedialog.askopenfilename(
            title="Select OLD Report (JSON)", filetypes=[("JSON files", "*.json")]
        )
        if not old_file:
            return

        new_file = filedialog.askopenfilename(
            title="Select NEW Report (JSON)", filetypes=[("JSON files", "*.json")]
        )
        if not new_file:
            return

        self.old_report_path = Path(old_file)
        self.new_report_path = Path(new_file)

        self.status_label.configure(
            text="📊 Both reports selected. Starting comparison..."
        )
        self._run_comparison()

    def _run_comparison(self):
        """Run comparison between two reports"""
        try:
            comparison_result = VersionComparator.compare(
                self.old_report_path, self.new_report_path
            )

            # Display comparison summary
            summary = comparison_result["summary"]
            output = f"""# 📊 Version Comparison Results

## Summary
- **Old Findings:** {summary["old_findings_count"]}
- **New Findings:** {summary["new_findings_count"]}
- **✅ Fixed (Removed):** {summary["removed"]}
- **⚠️ New (Added):** {summary["added"]}
- **🔄 Severity Changes:** {summary["severity_changes"]}

## ✅ Fixed Issues ({summary["removed"]})
"""
            if comparison_result["removed_findings"]:
                for finding in comparison_result["removed_findings"]:
                    output += f"\n- {finding['title']} (Severity: {finding.get('severity', 'INFO')})"
            else:
                output += "\nNo issues were fixed in this version."

            output += f"\n\n## ⚠️ New Issues ({summary['added']})"
            if comparison_result["added_findings"]:
                for finding in comparison_result["added_findings"]:
                    output += f"\n- {finding['title']} (Severity: {finding.get('severity', 'INFO')})"
            else:
                output += "\nNo new issues were introduced."

            self.compare_textbox.delete("1.0", "end")
            self.compare_textbox.insert("1.0", output)

            self.status_label.configure(text="✅ Comparison complete!")

        except Exception as e:
            self.compare_textbox.delete("1.0", "end")
            self.compare_textbox.insert("1.0", f"❌ Comparison failed: {str(e)}")
            self.status_label.configure(text="❌ Comparison failed")

    def toggle_html_report(self):
        """Toggle HTML report generation"""
        pass  # Checkbox state is tracked via .select() and .deselect()

    def toggle_persian_report(self):
        """Toggle Persian report generation"""
        pass

    def start_analysis(self):
        """Start analysis process"""
        if not self.apk_path:
            return

        # Disable buttons
        self.analyze_btn.configure(state="disabled", text="⏳ Analyzing...")
        self.select_btn.configure(state="disabled")
        self.progressbar.set(0.2)
        self.status_label.configure(text="🔄 Analyzing, please wait...")
        self.clear_output()

        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._run_analysis, daemon=True)
        self.analysis_thread.start()

    def _run_analysis(self):
        """Actual analysis execution"""
        try:
            # Build command with all scanners
            json_output = self.apk_path.parent / f"{self.apk_path.stem}_report.json"

            cmd = [
                sys.executable,
                "avs.py",
                str(self.apk_path),
                "--out",
                str(json_output),
                "--deep",
            ]

            self.progressbar.set(0.5)

            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8"
            )

            self.progressbar.set(0.8)

            if result.returncode == 0 and json_output.exists():
                self.json_report_path = json_output

                # Display JSON content
                with open(json_output, "r", encoding="utf-8") as f:
                    json_data = json.load(f)
                    pretty_json = json.dumps(json_data, indent=2, ensure_ascii=False)

                self.after(0, lambda: self._display_json(pretty_json))

                # Generate reports
                if self.persian_check.get() == 1:
                    try:
                        md_path = PersianReporter.generate_report(json_output)
                        with open(md_path, "r", encoding="utf-8") as f:
                            md_content = f.read()
                        self.after(0, lambda: self._display_persian(md_content))
                        self.persian_report_path = md_path
                    except Exception as e:
                        self.after(
                            0, lambda: self._display_persian(f"❌ Error: {str(e)}")
                        )

                if self.html_report_check.get() == 1:
                    try:
                        html_path = HTMLReporter.generate_report(json_output)
                        with open(html_path, "r", encoding="utf-8") as f:
                            html_content = f.read()
                        self.after(0, lambda: self._display_html(html_content))
                        self.html_report_path = html_path
                    except Exception as e:
                        self.after(0, lambda: self._display_html(f"❌ Error: {str(e)}"))

                self.after(0, self._enable_save_buttons)
                self.progressbar.set(1.0)
                self.after(
                    0,
                    lambda: self.status_label.configure(
                        text=f"✅ Analysis complete! {len(json_data.get('findings', []))} findings."
                    ),
                )

            else:
                error_msg = result.stderr if result.stderr else "Unknown error"
                self.after(0, lambda: self._display_json(f"❌ Error:\n{error_msg}"))
                self.progressbar.set(0)
                self.after(
                    0, lambda: self.status_label.configure(text="❌ Analysis failed")
                )

        except Exception as e:
            self.after(0, lambda: self._display_json(f"❌ Error:\n{str(e)}"))
            self.progressbar.set(0)
            self.after(
                0, lambda: self.status_label.configure(text="❌ Execution error")
            )

        finally:
            self.after(
                0,
                lambda: self.analyze_btn.configure(
                    state="normal", text="🔍 Re-analyze"
                ),
            )
            self.after(0, lambda: self.select_btn.configure(state="normal"))

    def _display_json(self, content):
        self.json_textbox.delete("1.0", "end")
        self.json_textbox.insert("1.0", content)

    def _display_persian(self, content):
        self.persian_textbox.delete("1.0", "end")
        self.persian_textbox.insert("1.0", content)

    def _display_html(self, content):
        self.html_textbox.delete("1.0", "end")
        self.html_textbox.insert("1.0", content)

    def _enable_save_buttons(self):
        self.save_json_btn.configure(state="normal")
        self.save_md_btn.configure(state="normal")
        self.save_html_btn.configure(state="normal")

    def save_json(self):
        """Save JSON file"""
        if not self.json_report_path:
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=self.json_report_path.name,
        )

        if save_path:
            import shutil

            shutil.copy(self.json_report_path, save_path)
            messagebox.showinfo("Success", f"JSON saved to {save_path}")

    def save_persian_report(self):
        """Save Persian report"""
        if not hasattr(self, "persian_report_path") or not self.persian_report_path:
            messagebox.showwarning("Warning", "No Persian report generated.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
            initialfile=self.persian_report_path.name,
        )

        if save_path:
            import shutil

            shutil.copy(self.persian_report_path, save_path)
            messagebox.showinfo("Success", f"Persian report saved to {save_path}")

    def save_html_report(self):
        """Save HTML report"""
        if not hasattr(self, "html_report_path") or not self.html_report_path:
            messagebox.showwarning("Warning", "No HTML report generated.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile=self.html_report_path.name,
        )

        if save_path:
            import shutil

            shutil.copy(self.html_report_path, save_path)
            messagebox.showinfo("Success", f"HTML report saved to {save_path}")

    def clear_output(self):
        """Clear all output tabs"""
        self.json_textbox.delete("1.0", "end")
        self.persian_textbox.delete("1.0", "end")
        self.html_textbox.delete("1.0", "end")
        self.compare_textbox.delete("1.0", "end")
        self.save_json_btn.configure(state="disabled")
        self.save_md_btn.configure(state="disabled")
        self.save_html_btn.configure(state="disabled")
        self.progressbar.set(0)


if __name__ == "__main__":
    app = ReAVSGUI()
    app.mainloop()
