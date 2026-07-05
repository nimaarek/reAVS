import json
import os
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Dict, List, Optional

import customtkinter as ctk

from database import ScanDatabase
from report_generator import ReportGenerator
from scanner_wrapper import ScannerWrapper


class ReAVSGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("reAVS Pro - Android Vulnerability Scanner")
        self.geometry("1400x900")
        self.configure(fg_color="#0a0e27")

        self.scanner = ScannerWrapper(progress_callback=self.progress_callback)
        self.database = ScanDatabase()
        self.report_gen = ReportGenerator()

        self.current_scan_id = None
        self.current_results = None
        self.apk_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.scan_mode = tk.StringVar(value="fast")
        self.depth = tk.IntVar(value=10)
        self.scanning = False
        self.log_visible = True

        self.setup_ui()

    def setup_ui(self):
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.setup_title_bar(main_frame)
        self.setup_content_area(main_frame)
        self.setup_progress_section(main_frame)
        self.setup_status_bar(main_frame)

    def setup_title_bar(self, parent):
        title_frame = ctk.CTkFrame(
            parent, fg_color="#1a1f3a", height=80, corner_radius=10
        )
        title_frame.pack(fill="x", pady=(0, 10))
        title_frame.pack_propagate(False)

        inner_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        inner_frame.pack(fill="both", expand=True, padx=20, pady=10)

        title_label = ctk.CTkLabel(
            inner_frame,
            text="⚡ reAVS Pro - Android Vulnerability Scanner ⚡",
            font=("Consolas", 26, "bold"),
            text_color="#00ff41",
        )
        title_label.pack(side="left", padx=10)

        subtitle = ctk.CTkLabel(
            inner_frame,
            text="Advanced Static Analysis & Malware Detection Tool",
            font=("Consolas", 11),
            text_color="#00d4ff",
        )
        subtitle.pack(side="left", padx=10, pady=25)

    def setup_content_area(self, parent):
        content_frame = ctk.CTkFrame(parent, fg_color="transparent")
        content_frame.pack(fill="both", expand=True, pady=5)

        left_panel = ctk.CTkFrame(
            content_frame,
            fg_color="#1a1f3a",
            corner_radius=10,
            border_width=2,
            border_color="#00ff41",
            width=380,
        )
        left_panel.pack(side="left", fill="y", padx=(0, 10))
        left_panel.pack_propagate(False)

        self.setup_left_content(left_panel)

        right_panel = ctk.CTkFrame(
            content_frame,
            fg_color="#1a1f3a",
            corner_radius=10,
            border_width=2,
            border_color="#00d4ff",
        )
        right_panel.pack(side="right", fill="both", expand=True)

        self.setup_right_content(right_panel)

    def setup_left_content(self, parent):
        scroll_frame = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkLabel(
            scroll_frame,
            text="🔧 SCAN CONFIGURATION",
            font=("Consolas", 13, "bold"),
            text_color="#00ff41",
        )
        header.pack(pady=(10, 15), anchor="w")

        self.setup_apk_selection(scroll_frame)
        self.setup_scan_options(scroll_frame)
        self.setup_action_buttons(scroll_frame)

    def setup_apk_selection(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="#0a0e27", corner_radius=8)
        frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            frame,
            text="📱 Target APK:",
            font=("Consolas", 11, "bold"),
            text_color="#00d4ff",
        ).pack(anchor="w", padx=10, pady=(10, 5))

        entry_frame = ctk.CTkFrame(frame, fg_color="transparent")
        entry_frame.pack(fill="x", padx=10, pady=(0, 10))

        apk_entry = ctk.CTkEntry(
            entry_frame,
            textvariable=self.apk_path,
            placeholder_text="Select APK file...",
            fg_color="#1a1f3a",
            border_color="#00ff41",
            text_color="#00ff41",
        )
        apk_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        browse_btn = ctk.CTkButton(
            entry_frame,
            text="Browse",
            command=self.browse_apk,
            width=80,
            fg_color="#0066ff",
            hover_color="#0052cc",
        )
        browse_btn.pack(side="right")

    def setup_scan_options(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="#0a0e27", corner_radius=8)
        frame.pack(fill="x", pady=10)

        ctk.CTkLabel(
            frame,
            text="⚡ Scan Mode:",
            font=("Consolas", 11, "bold"),
            text_color="#00d4ff",
        ).pack(anchor="w", padx=10, pady=(10, 5))

        mode_menu = ctk.CTkOptionMenu(
            frame,
            variable=self.scan_mode,
            values=["fast", "deep"],
            fg_color="#1a1f3a",
            button_color="#00ff41",
            button_hover_color="#00cc33",
        )
        mode_menu.pack(fill="x", padx=10, pady=(0, 10))

        ctk.CTkLabel(
            frame,
            text="🔍 Analysis Depth:",
            font=("Consolas", 11, "bold"),
            text_color="#00d4ff",
        ).pack(anchor="w", padx=10, pady=(10, 5))

        depth_slider = ctk.CTkSlider(
            frame,
            from_=1,
            to=20,
            number_of_steps=19,
            variable=self.depth,
            fg_color="#1a1f3a",
            button_color="#00ff41",
            button_hover_color="#00cc33",
            progress_color="#00ff41",
        )
        depth_slider.pack(fill="x", padx=10, pady=(0, 5))

        self.depth_label = ctk.CTkLabel(
            frame,
            text=f"Depth: {self.depth.get()}",
            font=("Consolas", 9),
            text_color="#00ff41",
        )
        self.depth_label.pack(anchor="e", padx=10, pady=(0, 10))

        depth_slider.configure(command=self.update_depth_label)

        ctk.CTkLabel(
            frame,
            text="💾 Output Location:",
            font=("Consolas", 11, "bold"),
            text_color="#00d4ff",
        ).pack(anchor="w", padx=10, pady=(10, 5))

        output_frame = ctk.CTkFrame(frame, fg_color="transparent")
        output_frame.pack(fill="x", padx=10, pady=(0, 10))

        output_entry = ctk.CTkEntry(
            output_frame,
            textvariable=self.output_path,
            placeholder_text="Select output directory...",
            fg_color="#1a1f3a",
            border_color="#00d4ff",
            text_color="#00d4ff",
        )
        output_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))

        output_btn = ctk.CTkButton(
            output_frame,
            text="Browse",
            command=self.browse_output,
            width=80,
            fg_color="#0066ff",
            hover_color="#0052cc",
        )
        output_btn.pack(side="right")

    def setup_action_buttons(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", pady=15)

        self.scan_btn = ctk.CTkButton(
            frame,
            text="🚀 START SCAN",
            command=self.start_scan,
            height=50,
            font=("Consolas", 14, "bold"),
            fg_color="#ff0055",
            hover_color="#cc0044",
            border_width=2,
            border_color="#ff0055",
        )
        self.scan_btn.pack(fill="x", pady=5)

        buttons = [
            ("📜 Scan History", self.show_history),
            ("🔄 Compare Versions", self.show_comparison),
            ("📝 Custom Rules", self.show_rules_editor),
        ]

        for text, command in buttons:
            btn = ctk.CTkButton(
                frame,
                text=text,
                command=command,
                height=40,
                fg_color="#0066ff",
                hover_color="#0052cc",
            )
            btn.pack(fill="x", pady=5)

    def setup_right_content(self, parent):
        scroll_frame = ctk.CTkScrollableFrame(parent, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkLabel(
            scroll_frame,
            text="📊 SCAN RESULTS",
            font=("Consolas", 13, "bold"),
            text_color="#00d4ff",
        )
        header.pack(pady=(10, 10), anchor="w")

        self.setup_filters(scroll_frame)
        self.setup_stats_panel(scroll_frame)
        self.setup_results_display(scroll_frame)
        self.setup_export_buttons(scroll_frame)

    def setup_filters(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="#0a0e27", corner_radius=8)
        frame.pack(fill="x", pady=10)

        inner_frame = ctk.CTkFrame(frame, fg_color="transparent")
        inner_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(
            inner_frame, text="🔍 Filter:", font=("Consolas", 10), text_color="#00d4ff"
        ).pack(side="left", padx=5)

        self.filter_var = tk.StringVar(value="all")
        filter_menu = ctk.CTkOptionMenu(
            inner_frame,
            variable=self.filter_var,
            values=["all", "critical", "high", "medium", "low"],
            command=self.apply_filter,
            width=120,
            fg_color="#1a1f3a",
            button_color="#00d4ff",
        )
        filter_menu.pack(side="left", padx=5)

        self.search_var = tk.StringVar()
        search_entry = ctk.CTkEntry(
            inner_frame,
            textvariable=self.search_var,
            placeholder_text="Search...",
            width=200,
            fg_color="#1a1f3a",
            border_color="#00d4ff",
        )
        search_entry.pack(side="left", padx=5)

        search_btn = ctk.CTkButton(
            inner_frame,
            text="Search",
            command=self.search_results,
            width=80,
            fg_color="#0066ff",
            hover_color="#0052cc",
        )
        search_btn.pack(side="left", padx=5)

    def setup_stats_panel(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="#0a0e27", corner_radius=8)
        frame.pack(fill="x", pady=10)

        stats_container = ctk.CTkFrame(frame, fg_color="transparent")
        stats_container.pack(fill="x", padx=10, pady=10)

        self.stats_labels = {}
        severities = [
            ("CRITICAL", "#ff0055"),
            ("HIGH", "#ff6600"),
            ("MEDIUM", "#ffcc00"),
            ("LOW", "#00ff41"),
        ]

        for i, (severity, color) in enumerate(severities):
            stat_frame = ctk.CTkFrame(
                stats_container, fg_color="#1a1f3a", corner_radius=8
            )
            stat_frame.grid(row=0, column=i, padx=5, pady=5, sticky="nsew")
            stats_container.grid_columnconfigure(i, weight=1)

            label = ctk.CTkLabel(
                stat_frame,
                text=f"{severity}\n0",
                font=("Consolas", 12, "bold"),
                text_color=color,
            )
            label.pack(padx=10, pady=15)
            self.stats_labels[severity] = label

    def setup_results_display(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="#0a0e27", corner_radius=8)
        frame.pack(fill="both", expand=True, pady=10)

        ctk.CTkLabel(
            frame,
            text="🔍 Vulnerability Details:",
            font=("Consolas", 11, "bold"),
            text_color="#00d4ff",
        ).pack(anchor="w", padx=10, pady=(10, 5))

        self.results_text = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#0a0e27",
            fg="#00ff41",
            insertbackground="#00ff41",
            borderwidth=0,
            height=15,
        )
        self.results_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def setup_export_buttons(self, parent):
        frame = ctk.CTkFrame(parent, fg_color="#0a0e27", corner_radius=8)
        frame.pack(fill="x", pady=10)

        btn_container = ctk.CTkFrame(frame, fg_color="transparent")
        btn_container.pack(fill="x", padx=10, pady=10)

        exports = [
            ("💾 JSON", "json"),
            ("📄 HTML (EN)", "html_en"),
            ("📄 HTML (FA)", "html_fa"),
            ("📊 CSV", "csv"),
            ("🔒 SARIF", "sarif"),
            ("📕 PDF", "pdf"),
        ]

        for text, fmt in exports:
            btn = ctk.CTkButton(
                btn_container,
                text=text,
                command=lambda f=fmt: self.export_results(f),
                width=100,
                height=35,
                fg_color="#0066ff",
                hover_color="#0052cc",
            )
            btn.pack(side="left", padx=3)

        clear_btn = ctk.CTkButton(
            btn_container,
            text="🗑️ Clear",
            command=self.clear_results,
            width=80,
            height=35,
            fg_color="#666666",
            hover_color="#555555",
        )
        clear_btn.pack(side="right", padx=3)

    def setup_progress_section(self, parent):
        self.progress_frame = ctk.CTkFrame(
            parent, fg_color="#1a1f3a", corner_radius=10, height=180
        )
        self.progress_frame.pack(fill="x", pady=5)

        header_frame = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(
            header_frame,
            text="📈 SCAN PROGRESS",
            font=("Consolas", 12, "bold"),
            text_color="#00ff41",
        ).pack(side="left", padx=5)

        self.toggle_btn = ctk.CTkButton(
            header_frame,
            text="▼ Hide Log",
            command=self.toggle_log,
            width=100,
            height=25,
            fg_color="#0066ff",
            hover_color="#0052cc",
            font=("Consolas", 9),
        )
        self.toggle_btn.pack(side="right", padx=5)

        progress_bar_frame = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        progress_bar_frame.pack(fill="x", padx=10, pady=5)

        self.progress_bar = ctk.CTkProgressBar(
            progress_bar_frame,
            height=25,
            fg_color="#0a0e27",
            progress_color="#00ff41",
            border_color="#00ff41",
            border_width=1,
        )
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.progress_bar.set(0)

        self.progress_percent = ctk.CTkLabel(
            progress_bar_frame,
            text="0%",
            font=("Consolas", 11, "bold"),
            text_color="#00ff41",
            width=60,
        )
        self.progress_percent.pack(side="right")

        self.progress_log = scrolledtext.ScrolledText(
            self.progress_frame,
            height=6,
            font=("Consolas", 9),
            bg="#0a0e27",
            fg="#00d4ff",
            insertbackground="#00d4ff",
            borderwidth=0,
        )
        self.progress_log.pack(fill="x", padx=10, pady=(0, 10))

    def setup_status_bar(self, parent):
        status_frame = ctk.CTkFrame(
            parent, fg_color="#1a1f3a", corner_radius=10, height=40
        )
        status_frame.pack(fill="x", pady=(5, 0))
        status_frame.pack_propagate(False)

        inner_frame = ctk.CTkFrame(status_frame, fg_color="transparent")
        inner_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.status_label = ctk.CTkLabel(
            inner_frame,
            text="⚡ Ready to scan...",
            font=("Consolas", 11, "bold"),
            text_color="#00ff41",
        )
        self.status_label.pack(side="left", padx=10)

        self.time_label = ctk.CTkLabel(
            inner_frame, text="", font=("Consolas", 10), text_color="#00d4ff"
        )
        self.time_label.pack(side="right", padx=10)

    def toggle_log(self):
        if self.log_visible:
            self.progress_log.pack_forget()
            self.toggle_btn.configure(text="▶ Show Log")
            self.log_visible = False
        else:
            self.progress_log.pack(fill="x", padx=10, pady=(0, 10))
            self.toggle_btn.configure(text="▼ Hide Log")
            self.log_visible = True

    def progress_callback(self, stage: str, progress: float, message: str):
        try:
            self.after(0, lambda: self.update_progress(stage, progress, message))
        except Exception as e:
            print(f"[!] Progress callback error: {e}")

    def update_progress(self, stage: str, progress: float, message: str):
        try:
            self.progress_bar.set(progress)
            percent_text = f"{int(progress * 100)}%"
            self.progress_percent.configure(text=percent_text)
            self.status_label.configure(text=f"⚡ {message}")

            timestamp = datetime.now().strftime("%H:%M:%S")
            log_msg = f"[{timestamp}] {message}\n"
            self.progress_log.insert(tk.END, log_msg)
            self.progress_log.see(tk.END)
        except Exception as e:
            print(f"[!] Update progress error: {e}")

    def update_depth_label(self, value):
        self.depth_label.configure(text=f"Depth: {int(value)}")

    def browse_apk(self):
        filename = filedialog.askopenfilename(
            title="Select APK File",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")],
        )
        if filename:
            self.apk_path.set(filename)

    def browse_output(self):
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_path.set(directory)

    def start_scan(self):
        if not self.apk_path.get():
            messagebox.showerror("Error", "Please select an APK file!")
            return

        if not os.path.exists(self.apk_path.get()):
            messagebox.showerror("Error", "APK file not found!")
            return

        self.scanning = True
        self.scan_start_time = datetime.now()
        self.scan_btn.configure(state="disabled", text="⏳ SCANNING...")

        self.progress_bar.set(0)
        self.progress_percent.configure(text="0%")
        self.status_label.configure(text="⚡ Initializing scan...")
        self.progress_log.delete(1.0, tk.END)
        self.results_text.delete(1.0, tk.END)

        self.time_label.configure(text="⏱️ 00:00")
        self.start_time_counter()

        thread = threading.Thread(target=self.run_scan)
        thread.daemon = True
        thread.start()

    def start_time_counter(self):
        if self.scanning:
            elapsed = datetime.now() - self.scan_start_time
            minutes, seconds = divmod(int(elapsed.total_seconds()), 60)
            self.time_label.configure(text=f"⏱️ {minutes:02d}:{seconds:02d}")
            self.after(1000, self.start_time_counter)

    def run_scan(self):
        try:
            print(f"[GUI] Starting scan for: {self.apk_path.get()}")
            print(f"[GUI] Mode: {self.scan_mode.get()}, Depth: {self.depth.get()}")

            results = self.scanner.scan(
                apk_path=self.apk_path.get(),
                mode=self.scan_mode.get(),
                depth=self.depth.get(),
                output_file=None,
            )

            print(f"[GUI] Scan completed. Status: {results.get('status', 'unknown')}")
            print(
                f"[GUI] Vulnerabilities found: {len(results.get('vulnerabilities', []))}"
            )

            if results.get("status") != "error" and results.get("status") != "timeout":
                self.current_results = results
                self.current_scan_id = self.database.save_scan(
                    apk_path=self.apk_path.get(),
                    scan_mode=self.scan_mode.get(),
                    depth=self.depth.get(),
                    results=results,
                )

                self.after(0, lambda: self.display_results(results))
                self.after(
                    0,
                    lambda: self.status_label.configure(
                        text=f"✅ Scan completed! Found {len(results.get('vulnerabilities', []))} vulnerabilities"
                    ),
                )
            else:
                error_msg = results.get("error", "Unknown error")
                print(f"[GUI] Scan error: {error_msg}")
                self.after(
                    0,
                    lambda: self.results_text.insert(
                        tk.END, f"❌ Error: {error_msg}\n"
                    ),
                )
                self.after(
                    0, lambda: self.status_label.configure(text="❌ Scan failed!")
                )

        except Exception as e:
            print(f"[GUI] Exception in run_scan: {e}")
            import traceback

            traceback.print_exc()
            self.after(
                0, lambda: self.status_label.configure(text="❌ Error occurred!")
            )
            self.after(
                0, lambda: self.results_text.insert(tk.END, f"Exception: {str(e)}\n")
            )

        finally:
            self.scanning = False
            self.after(
                0, lambda: self.scan_btn.configure(state="normal", text="🚀 START SCAN")
            )

    def display_results(self, results: Dict[str, Any]):
        vulns = results.get("vulnerabilities", [])

        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulns:
            severity = vuln.get("severity", "LOW").upper()
            if severity in stats:
                stats[severity] += 1

        for severity, count in stats.items():
            label = self.stats_labels[severity]
            label.configure(text=f"{severity}\n{count}")

        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, "=" * 80 + "\n")
        self.results_text.insert(tk.END, "SCAN RESULTS SUMMARY\n")
        self.results_text.insert(tk.END, "=" * 80 + "\n\n")

        self.results_text.insert(tk.END, f"Total Vulnerabilities: {len(vulns)}\n")
        self.results_text.insert(tk.END, f"Scan Mode: {self.scan_mode.get().upper()}\n")
        self.results_text.insert(
            tk.END, f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )

        if results.get("components"):
            self.results_text.insert(tk.END, "Components:\n")
            for comp, count in results["components"].items():
                self.results_text.insert(tk.END, f"  - {comp}: {count}\n")
            self.results_text.insert(tk.END, "\n")

        if results.get("methods"):
            self.results_text.insert(tk.END, "Methods:\n")
            for key, value in results["methods"].items():
                self.results_text.insert(tk.END, f"  - {key}: {value}\n")
            self.results_text.insert(tk.END, "\n")

        self.results_text.insert(tk.END, "=" * 80 + "\n")
        self.results_text.insert(tk.END, "VULNERABILITY DETAILS\n")
        self.results_text.insert(tk.END, "=" * 80 + "\n\n")

        for i, vuln in enumerate(vulns, 1):
            severity = vuln.get("severity", "UNKNOWN").upper()
            self.results_text.insert(
                tk.END, f"[{i}] {severity} - {vuln.get('type', 'Unknown')}\n"
            )
            self.results_text.insert(
                tk.END, f"    Location: {vuln.get('location', 'N/A')}\n"
            )
            self.results_text.insert(
                tk.END, f"    Component: {vuln.get('component', 'N/A')}\n"
            )
            self.results_text.insert(
                tk.END, f"    Description: {vuln.get('description', 'N/A')}\n"
            )
            self.results_text.insert(tk.END, f"    Risk: {vuln.get('risk', 'N/A')}\n")

            if "code_flow" in vuln and vuln["code_flow"]:
                self.results_text.insert(tk.END, "    Code Flow:\n")
                for step in vuln["code_flow"]:
                    self.results_text.insert(tk.END, f"      → {step}\n")

            self.results_text.insert(tk.END, "-" * 80 + "\n\n")

    def apply_filter(self, choice):
        if not self.current_results:
            return

        filter_type = self.filter_var.get()
        vulns = self.current_results.get("vulnerabilities", [])

        if filter_type == "all":
            filtered = vulns
        else:
            filtered = [
                v for v in vulns if v.get("severity", "").upper() == filter_type.upper()
            ]

        self.display_filtered_results(filtered)

    def search_results(self):
        if not self.current_results:
            return

        search_term = self.search_var.get().lower()
        if not search_term:
            self.display_results(self.current_results)
            return

        vulns = self.current_results.get("vulnerabilities", [])
        filtered = [
            v
            for v in vulns
            if search_term in v.get("type", "").lower()
            or search_term in v.get("description", "").lower()
            or search_term in v.get("location", "").lower()
        ]

        self.display_filtered_results(filtered)

    def display_filtered_results(self, vulns: List[Dict[str, Any]]):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Showing {len(vulns)} vulnerabilities\n")
        self.results_text.insert(tk.END, "=" * 80 + "\n\n")

        for i, vuln in enumerate(vulns, 1):
            severity = vuln.get("severity", "UNKNOWN").upper()
            self.results_text.insert(
                tk.END, f"[{i}] {severity} - {vuln.get('type', 'Unknown')}\n"
            )
            self.results_text.insert(
                tk.END, f"    Location: {vuln.get('location', 'N/A')}\n"
            )
            self.results_text.insert(
                tk.END, f"    Description: {vuln.get('description', 'N/A')}\n"
            )
            self.results_text.insert(tk.END, "-" * 80 + "\n\n")

    def export_results(self, format_type: str):
        if not self.current_results:
            messagebox.showwarning("Warning", "No results to export!")
            return

        filetypes = {
            "json": [("JSON files", "*.json")],
            "html_en": [("HTML files", "*.html")],
            "html_fa": [("HTML files", "*.html")],
            "csv": [("CSV files", "*.csv")],
            "sarif": [("SARIF files", "*.sarif")],
            "pdf": [("PDF files", "*.pdf")],
        }

        filename = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=f".{format_type.split('_')[0]}",
            filetypes=filetypes.get(format_type, [("All files", "*.*")]),
        )

        if not filename:
            return

        try:
            apk_name = os.path.basename(self.apk_path.get())

            if format_type == "json":
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(self.current_results, f, indent=2, ensure_ascii=False)

            elif format_type == "html_en":
                self.report_gen.generate_html_report(
                    self.current_results, apk_name, "en", filename
                )

            elif format_type == "html_fa":
                self.report_gen.generate_html_report(
                    self.current_results, apk_name, "fa", filename
                )

            elif format_type == "csv":
                self.report_gen.generate_csv(self.current_results, filename)

            elif format_type == "sarif":
                self.report_gen.generate_sarif(self.current_results, filename)

            elif format_type == "pdf":
                self.report_gen.generate_pdf(self.current_results, apk_name, filename)

            messagebox.showinfo("Success", f"Results exported to {filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        for label in self.stats_labels.values():
            label.configure(text=f"{label.cget('text').split()[0]}\n0")
        self.status_label.configure(text="⚡ Ready to scan...")
        self.progress_bar.set(0)
        self.progress_percent.configure(text="0%")
        self.progress_log.delete(1.0, tk.END)
        self.current_results = None
        self.current_scan_id = None

    def show_history(self):
        history_window = ctk.CTkToplevel(self)
        history_window.title("Scan History")
        history_window.geometry("800x600")
        history_window.configure(fg_color="#0a0e27")

        header = ctk.CTkLabel(
            history_window,
            text="📜 Scan History",
            font=("Consolas", 18, "bold"),
            text_color="#00ff41",
        )
        header.pack(pady=10)

        columns = (
            "ID",
            "APK Name",
            "Mode",
            "Depth",
            "Date",
            "Total",
            "Critical",
            "High",
            "Medium",
            "Low",
        )
        tree = ttk.Treeview(history_window, columns=columns, show="headings")

        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=80)

        history = self.database.get_scan_history()
        for scan in history:
            tree.insert(
                "",
                "end",
                values=(
                    scan["id"],
                    scan["apk_name"],
                    scan["scan_mode"],
                    scan["depth"],
                    scan["timestamp"][:19],
                    scan["total_vulns"],
                    scan["critical"],
                    scan["high"],
                    scan["medium"],
                    scan["low"],
                ),
            )

        tree.pack(fill="both", expand=True, padx=20, pady=10)

        def load_scan():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select a scan!")
                return

            item = tree.item(selected[0])
            scan_id = item["values"][0]

            scan_data = self.database.get_scan_by_id(scan_id)
            if scan_data:
                self.current_results = scan_data["results"]
                self.current_scan_id = scan_id
                self.display_results(self.current_results)
                history_window.destroy()

        load_btn = ctk.CTkButton(
            history_window,
            text="Load Selected Scan",
            command=load_scan,
            fg_color="#0066ff",
            hover_color="#0052cc",
        )
        load_btn.pack(pady=10)

    def show_comparison(self):
        compare_window = ctk.CTkToplevel(self)
        compare_window.title("Compare Versions")
        compare_window.geometry("600x400")
        compare_window.configure(fg_color="#0a0e27")

        header = ctk.CTkLabel(
            compare_window,
            text="🔄 Compare Scan Versions",
            font=("Consolas", 18, "bold"),
            text_color="#00ff41",
        )
        header.pack(pady=10)

        history = self.database.get_scan_history()
        if len(history) < 2:
            messagebox.showwarning("Warning", "Need at least 2 scans to compare!")
            compare_window.destroy()
            return

        scan_names = [
            f"{s['id']}: {s['apk_name']} ({s['timestamp'][:10]})" for s in history
        ]

        ctk.CTkLabel(
            compare_window,
            text="Select First Scan:",
            font=("Consolas", 12),
            text_color="#00d4ff",
        ).pack(pady=5)

        scan1_var = tk.StringVar(value=scan_names[0])
        scan1_menu = ctk.CTkOptionMenu(
            compare_window, variable=scan1_var, values=scan_names, width=400
        )
        scan1_menu.pack(pady=5)

        ctk.CTkLabel(
            compare_window,
            text="Select Second Scan:",
            font=("Consolas", 12),
            text_color="#00d4ff",
        ).pack(pady=5)

        scan2_var = tk.StringVar(
            value=scan_names[1] if len(scan_names) > 1 else scan_names[0]
        )
        scan2_menu = ctk.CTkOptionMenu(
            compare_window, variable=scan2_var, values=scan_names, width=400
        )
        scan2_menu.pack(pady=5)

        def compare():
            id1 = int(scan1_var.get().split(":")[0])
            id2 = int(scan2_var.get().split(":")[0])

            comparison = self.database.compare_versions(id1, id2)

            if "error" in comparison:
                messagebox.showerror("Error", comparison["error"])
                return

            result_window = ctk.CTkToplevel(self)
            result_window.title("Comparison Results")
            result_window.geometry("700x500")
            result_window.configure(fg_color="#0a0e27")

            text = scrolledtext.ScrolledText(
                result_window, font=("Consolas", 10), bg="#0a0e27", fg="#00ff41"
            )
            text.pack(fill="both", expand=True, padx=20, pady=20)

            text.insert(tk.END, "=" * 80 + "\n")
            text.insert(tk.END, "VERSION COMPARISON RESULTS\n")
            text.insert(tk.END, "=" * 80 + "\n\n")

            text.insert(tk.END, f"New Vulnerabilities: {comparison['stats']['new']}\n")
            text.insert(
                tk.END, f"Fixed Vulnerabilities: {comparison['stats']['fixed']}\n"
            )
            text.insert(
                tk.END, f"Common Vulnerabilities: {comparison['stats']['common']}\n\n"
            )

            if comparison["new_vulnerabilities"]:
                text.insert(tk.END, "\nNEW VULNERABILITIES:\n")
                text.insert(tk.END, "-" * 80 + "\n")
                for vuln in comparison["new_vulnerabilities"]:
                    text.insert(
                        tk.END,
                        f"- {vuln.get('type', 'Unknown')} [{vuln.get('severity', 'N/A')}]\n",
                    )

            if comparison["fixed_vulnerabilities"]:
                text.insert(tk.END, "\nFIXED VULNERABILITIES:\n")
                text.insert(tk.END, "-" * 80 + "\n")
                for vuln in comparison["fixed_vulnerabilities"]:
                    text.insert(
                        tk.END,
                        f"- {vuln.get('type', 'Unknown')} [{vuln.get('severity', 'N/A')}]\n",
                    )

        compare_btn = ctk.CTkButton(
            compare_window,
            text="Compare",
            command=compare,
            fg_color="#0066ff",
            hover_color="#0052cc",
        )
        compare_btn.pack(pady=20)

    def show_rules_editor(self):
        rules_window = ctk.CTkToplevel(self)
        rules_window.title("Custom Rules Editor")
        rules_window.geometry("800x600")
        rules_window.configure(fg_color="#0a0e27")

        header = ctk.CTkLabel(
            rules_window,
            text="📝 Custom Rules Editor",
            font=("Consolas", 18, "bold"),
            text_color="#00ff41",
        )
        header.pack(pady=10)

        form_frame = ctk.CTkFrame(rules_window, fg_color="#1a1f3a")
        form_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(
            form_frame, text="Rule Name:", font=("Consolas", 11), text_color="#00d4ff"
        ).grid(row=0, column=0, padx=10, pady=5, sticky="w")

        name_entry = ctk.CTkEntry(form_frame, width=300)
        name_entry.grid(row=0, column=1, padx=10, pady=5)

        ctk.CTkLabel(
            form_frame, text="Rule Type:", font=("Consolas", 11), text_color="#00d4ff"
        ).grid(row=1, column=0, padx=10, pady=5, sticky="w")

        type_var = tk.StringVar(value="source")
        type_menu = ctk.CTkOptionMenu(
            form_frame,
            variable=type_var,
            values=["source", "sink", "sanitizer"],
            width=300,
        )
        type_menu.grid(row=1, column=1, padx=10, pady=5)

        ctk.CTkLabel(
            form_frame, text="Pattern:", font=("Consolas", 11), text_color="#00d4ff"
        ).grid(row=2, column=0, padx=10, pady=5, sticky="w")

        pattern_entry = ctk.CTkEntry(form_frame, width=300)
        pattern_entry.grid(row=2, column=1, padx=10, pady=5)

        ctk.CTkLabel(
            form_frame, text="Severity:", font=("Consolas", 11), text_color="#00d4ff"
        ).grid(row=3, column=0, padx=10, pady=5, sticky="w")

        severity_var = tk.StringVar(value="MEDIUM")
        severity_menu = ctk.CTkOptionMenu(
            form_frame,
            variable=severity_var,
            values=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            width=300,
        )
        severity_menu.grid(row=3, column=1, padx=10, pady=5)

        ctk.CTkLabel(
            form_frame, text="Description:", font=("Consolas", 11), text_color="#00d4ff"
        ).grid(row=4, column=0, padx=10, pady=5, sticky="w")

        desc_entry = ctk.CTkEntry(form_frame, width=300)
        desc_entry.grid(row=4, column=1, padx=10, pady=5)

        def add_rule():
            name = name_entry.get()
            if not name:
                messagebox.showwarning("Warning", "Please enter a rule name!")
                return

            success = self.database.save_custom_rule(
                rule_name=name,
                rule_type=type_var.get(),
                pattern=pattern_entry.get(),
                severity=severity_var.get(),
                description=desc_entry.get(),
            )

            if success:
                messagebox.showinfo("Success", "Rule added successfully!")
                load_rules()
            else:
                messagebox.showerror("Error", "Failed to add rule!")

        add_btn = ctk.CTkButton(
            form_frame,
            text="Add Rule",
            command=add_rule,
            fg_color="#0066ff",
            hover_color="#0052cc",
        )
        add_btn.grid(row=5, column=0, columnspan=2, pady=10)

        rules_list = scrolledtext.ScrolledText(
            rules_window, font=("Consolas", 10), bg="#0a0e27", fg="#00ff41"
        )
        rules_list.pack(fill="both", expand=True, padx=20, pady=10)

        def load_rules():
            rules_list.delete(1.0, tk.END)
            rules = self.database.get_custom_rules()

            if not rules:
                rules_list.insert(tk.END, "No custom rules defined.\n")
                return

            for rule in rules:
                rules_list.insert(tk.END, f"[{rule['id']}] {rule['name']}\n")
                rules_list.insert(tk.END, f"    Type: {rule['type']}\n")
                rules_list.insert(tk.END, f"    Pattern: {rule['pattern']}\n")
                rules_list.insert(tk.END, f"    Severity: {rule['severity']}\n")
                rules_list.insert(tk.END, f"    Description: {rule['description']}\n")
                rules_list.insert(
                    tk.END, f"    Enabled: {'Yes' if rule['enabled'] else 'No'}\n"
                )
                rules_list.insert(tk.END, "-" * 80 + "\n\n")

        load_rules()


if __name__ == "__main__":
    app = ReAVSGUI()
    app.mainloop()
