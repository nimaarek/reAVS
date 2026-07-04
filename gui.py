import json
import subprocess
import sys
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.persian_reporter import PersianReporter

# Appearance settings
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


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
        self.analysis_thread = None

        # Build widgets
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

    def start_analysis(self):
        """Start analysis process in a separate thread"""
        if not self.apk_path:
            return

        # Disable buttons during analysis
        self.analyze_btn.configure(state="disabled", text="⏳ Analyzing...")
        self.select_btn.configure(state="disabled")
        self.progressbar.set(0.2)
        self.status_label.configure(text="🔄 Analyzing, please wait...")
        self.clear_output()

        # Run analysis in thread
        self.analysis_thread = threading.Thread(target=self._run_analysis, daemon=True)
        self.analysis_thread.start()

    def _run_analysis(self):
        """Actual analysis execution (runs in separate thread)"""
        try:
            # Build command
            json_output = self.apk_path.parent / f"{self.apk_path.stem}_report.json"

            cmd = [
                sys.executable,
                "avs.py",
                str(self.apk_path),
                "--out",
                str(json_output),
                "--deep",  # Default to deep mode for comprehensive results
            ]

            self.progressbar.set(0.5)

            # Execute and capture output
            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8"
            )

            self.progressbar.set(0.8)

            # Display results in GUI
            if result.returncode == 0 and json_output.exists():
                self.json_report_path = json_output

                # Display JSON content
                with open(json_output, "r", encoding="utf-8") as f:
                    json_data = json.load(f)
                    pretty_json = json.dumps(json_data, indent=2, ensure_ascii=False)

                self.after(0, lambda: self._display_json(pretty_json))

                # Generate Persian report
                try:
                    md_path = PersianReporter.generate_report(json_output)
                    with open(md_path, "r", encoding="utf-8") as f:
                        md_content = f.read()
                    self.after(0, lambda: self._display_persian(md_content))

                    # Store Persian report path
                    self.persian_report_path = md_path

                except Exception as e:
                    self.after(
                        0,
                        lambda: self._display_persian(
                            f"❌ Error generating Persian report:\n{str(e)}"
                        ),
                    )

                self.after(0, self._enable_save_buttons)
                self.progressbar.set(1.0)
                self.after(
                    0,
                    lambda: self.status_label.configure(
                        text=f"✅ Analysis complete! {len(json_data.get('findings', []))} findings identified."
                    ),
                )

            else:
                error_msg = (
                    result.stderr if result.stderr else "Unknown error during analysis"
                )
                self.after(
                    0, lambda: self._display_json(f"❌ Analysis error:\n{error_msg}")
                )
                self.progressbar.set(0)
                self.after(
                    0, lambda: self.status_label.configure(text="❌ Analysis failed")
                )

        except Exception as e:
            self.after(0, lambda: self._display_json(f"❌ Unexpected error:\n{str(e)}"))
            self.progressbar.set(0)
            self.after(
                0, lambda: self.status_label.configure(text="❌ Execution error")
            )

        finally:
            # Re-enable buttons
            self.after(
                0,
                lambda: self.analyze_btn.configure(
                    state="normal", text="🔍 Re-analyze"
                ),
            )
            self.after(0, lambda: self.select_btn.configure(state="normal"))

    def _display_json(self, content):
        """Display content in JSON tab"""
        self.json_textbox.delete("1.0", "end")
        self.json_textbox.insert("1.0", content)

    def _display_persian(self, content):
        """Display content in Persian report tab"""
        self.persian_textbox.delete("1.0", "end")
        self.persian_textbox.insert("1.0", content)

    def _enable_save_buttons(self):
        """Enable save buttons"""
        self.save_json_btn.configure(state="normal")
        self.save_md_btn.configure(state="normal")

    def save_json(self):
        """Save JSON file with user-selected path"""
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
            messagebox.showinfo("Success", f"JSON file saved to {save_path}")

    def save_persian_report(self):
        """Save Persian report with user-selected path"""
        if not hasattr(self, "persian_report_path") or not self.persian_report_path:
            messagebox.showwarning(
                "Warning", "No Persian report has been generated yet."
            )
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

    def clear_output(self):
        """Clear content from both tabs"""
        self.json_textbox.delete("1.0", "end")
        self.persian_textbox.delete("1.0", "end")
        self.save_json_btn.configure(state="disabled")
        self.save_md_btn.configure(state="disabled")
        self.progressbar.set(0)


if __name__ == "__main__":
    app = ReAVSGUI()
    app.mainloop()
