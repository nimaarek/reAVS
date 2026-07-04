import json
import subprocess
import sys
import threading
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.persian_reporter import PersianReporter

# تنظیمات ظاهری
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class ReAVSGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("reAVS - تحلیلگر امنیتی اندروید")
        self.geometry("900x700")
        self.minsize(800, 600)

        # متغیرها
        self.apk_path = None
        self.json_report_path = None
        self.analysis_thread = None

        # ساخت ویجت‌ها
        self._create_widgets()

    def _create_widgets(self):
        """ساخت تمام ویجت‌های رابط کاربری"""

        # ===== فریم بالا (انتخاب فایل) =====
        self.top_frame = ctk.CTkFrame(self)
        self.top_frame.pack(pady=10, padx=20, fill="x")

        self.file_label = ctk.CTkLabel(
            self.top_frame, text="هیچ فایلی انتخاب نشده است", font=("IRANSans", 12)
        )
        self.file_label.pack(side="left", padx=10)

        self.select_btn = ctk.CTkButton(
            self.top_frame, text="📂 انتخاب APK", command=self.select_apk, width=120
        )
        self.select_btn.pack(side="right", padx=10)

        # ===== فریم میانی (کنترل‌ها) =====
        self.mid_frame = ctk.CTkFrame(self)
        self.mid_frame.pack(pady=10, padx=20, fill="x")

        # دکمه شروع تحلیل
        self.analyze_btn = ctk.CTkButton(
            self.mid_frame,
            text="🔍 شروع تحلیل",
            command=self.start_analysis,
            state="disabled",
            height=40,
            font=("IRANSans", 14, "bold"),
        )
        self.analyze_btn.pack(pady=5)

        # نوار پیشرفت
        self.progressbar = ctk.CTkProgressBar(self.mid_frame)
        self.progressbar.pack(pady=5, fill="x")
        self.progressbar.set(0)

        # وضعیت
        self.status_label = ctk.CTkLabel(
            self.mid_frame, text="⏳ منتظر انتخاب فایل...", font=("IRANSans", 11)
        )
        self.status_label.pack(pady=5)

        # ===== فریم پایین (نمایش خروجی) =====
        self.bottom_frame = ctk.CTkFrame(self)
        self.bottom_frame.pack(pady=10, padx=20, fill="both", expand=True)

        # تب‌ها
        self.tabview = ctk.CTkTabview(self.bottom_frame)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)

        # تب خروجی JSON
        self.tab_json = self.tabview.add("📄 خروجی JSON")
        self.json_textbox = ctk.CTkTextbox(self.tab_json, wrap="none")
        self.json_textbox.pack(fill="both", expand=True)

        # تب گزارش فارسی
        self.tab_persian = self.tabview.add("🇮🇷 گزارش فارسی")
        self.persian_textbox = ctk.CTkTextbox(self.tab_persian, wrap="word")
        self.persian_textbox.pack(fill="both", expand=True)

        # دکمه‌های پایین
        self.btn_frame = ctk.CTkFrame(self)
        self.btn_frame.pack(pady=10, padx=20, fill="x")

        self.save_json_btn = ctk.CTkButton(
            self.btn_frame,
            text="💾 ذخیره JSON",
            command=self.save_json,
            state="disabled",
            width=120,
        )
        self.save_json_btn.pack(side="left", padx=5)

        self.save_md_btn = ctk.CTkButton(
            self.btn_frame,
            text="📝 ذخیره گزارش فارسی",
            command=self.save_persian_report,
            state="disabled",
            width=150,
        )
        self.save_md_btn.pack(side="left", padx=5)

        self.clear_btn = ctk.CTkButton(
            self.btn_frame,
            text="🗑️ پاک کردن خروجی",
            command=self.clear_output,
            width=120,
        )
        self.clear_btn.pack(side="right", padx=5)

    def select_apk(self):
        """انتخاب فایل APK توسط کاربر"""
        file_path = filedialog.askopenfilename(
            title="انتخاب فایل APK",
            filetypes=[("APK files", "*.apk"), ("All files", "*.*")],
        )

        if file_path:
            self.apk_path = Path(file_path)
            self.file_label.configure(text=f"✅ {self.apk_path.name}")
            self.analyze_btn.configure(state="normal")
            self.status_label.configure(text="✅ فایل انتخاب شد. آماده برای تحلیل.")

    def start_analysis(self):
        """شروع فرآیند تحلیل در یک ترد جداگانه"""
        if not self.apk_path:
            return

        # غیرفعال کردن دکمه‌ها
        self.analyze_btn.configure(state="disabled", text="⏳ در حال تحلیل...")
        self.select_btn.configure(state="disabled")
        self.progressbar.set(0.2)
        self.status_label.configure(text="🔄 در حال تحلیل، لطفاً صبر کنید...")
        self.clear_output()

        # اجرای تحلیل در ترد
        self.analysis_thread = threading.Thread(target=self._run_analysis, daemon=True)
        self.analysis_thread.start()

    def _run_analysis(self):
        """اجرای واقعی تحلیل (در ترد جداگانه)"""
        try:
            # اجرای دستور avs.py
            json_output = self.apk_path.parent / f"{self.apk_path.stem}_report.json"

            cmd = [
                sys.executable,
                "avs.py",
                str(self.apk_path),
                "--out",
                str(json_output),
                "--deep",  # حالت پیش‌فرض deep برای گزارش کامل‌تر
            ]

            self.progressbar.set(0.5)

            # اجرا و گرفتن خروجی
            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8"
            )

            self.progressbar.set(0.8)

            # نمایش خروجی در GUI
            if result.returncode == 0 and json_output.exists():
                self.json_report_path = json_output

                # نمایش محتوای JSON
                with open(json_output, "r", encoding="utf-8") as f:
                    json_data = json.load(f)
                    pretty_json = json.dumps(json_data, indent=2, ensure_ascii=False)

                self.after(0, lambda: self._display_json(pretty_json))

                # تولید گزارش فارسی
                try:
                    md_path = PersianReporter.generate_report(json_output)
                    with open(md_path, "r", encoding="utf-8") as f:
                        md_content = f.read()
                    self.after(0, lambda: self._display_persian(md_content))

                    # ذخیره مسیر گزارش فارسی
                    self.persian_report_path = md_path

                except Exception as e:
                    self.after(
                        0,
                        lambda: self._display_persian(
                            f"❌ خطا در تولید گزارش فارسی:\n{str(e)}"
                        ),
                    )

                self.after(0, self._enable_save_buttons)
                self.progressbar.set(1.0)
                self.after(
                    0,
                    lambda: self.status_label.configure(
                        text=f"✅ تحلیل کامل شد! {len(json_data.get('findings', []))} یافته شناسایی شد."
                    ),
                )

            else:
                error_msg = (
                    result.stderr if result.stderr else "خطای ناشناخته در حین تحلیل"
                )
                self.after(
                    0, lambda: self._display_json(f"❌ خطا در تحلیل:\n{error_msg}")
                )
                self.progressbar.set(0)
                self.after(
                    0,
                    lambda: self.status_label.configure(
                        text="❌ تحلیل با خطا مواجه شد"
                    ),
                )

        except Exception as e:
            self.after(0, lambda: self._display_json(f"❌ خطای غیرمنتظره:\n{str(e)}"))
            self.progressbar.set(0)
            self.after(0, lambda: self.status_label.configure(text="❌ خطا در اجرا"))

        finally:
            # فعال‌سازی مجدد دکمه‌ها
            self.after(
                0,
                lambda: self.analyze_btn.configure(
                    state="normal", text="🔍 شروع تحلیل مجدد"
                ),
            )
            self.after(0, lambda: self.select_btn.configure(state="normal"))

    def _display_json(self, content):
        """نمایش محتوا در تب JSON"""
        self.json_textbox.delete("1.0", "end")
        self.json_textbox.insert("1.0", content)

    def _display_persian(self, content):
        """نمایش محتوا در تب گزارش فارسی"""
        self.persian_textbox.delete("1.0", "end")
        self.persian_textbox.insert("1.0", content)

    def _enable_save_buttons(self):
        """فعال کردن دکمه‌های ذخیره"""
        self.save_json_btn.configure(state="normal")
        self.save_md_btn.configure(state="normal")

    def save_json(self):
        """ذخیره فایل JSON با انتخاب مسیر توسط کاربر"""
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
            messagebox.showinfo("موفق", f"فایل JSON در {save_path} ذخیره شد.")

    def save_persian_report(self):
        """ذخیره گزارش فارسی با انتخاب مسیر توسط کاربر"""
        if not hasattr(self, "persian_report_path"):
            messagebox.showwarning("اخطار", "هنوز گزارش فارسی تولید نشده است.")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
            initialfile=self.persian_report_path.name,
        )

        if save_path:
            import shutil

            shutil.copy(self.persian_report_path, save_path)
            messagebox.showinfo("موفق", f"گزارش فارسی در {save_path} ذخیره شد.")

    def clear_output(self):
        """پاک کردن محتوای هر دو تب"""
        self.json_textbox.delete("1.0", "end")
        self.persian_textbox.delete("1.0", "end")
        self.save_json_btn.configure(state="disabled")
        self.save_md_btn.configure(state="disabled")
        self.progressbar.set(0)


if __name__ == "__main__":
    app = ReAVSGUI()
    app.mainloop()
