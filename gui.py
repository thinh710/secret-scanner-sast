from __future__ import annotations

import threading
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from scanner.scanner import Scanner
from scanner.reporter import save_csv, save_html, save_json
from scanner.fix_advisor import save_guidance

SEVERITY_LEVELS = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secret Scanner (Secrets + SAST) - GUI")
        self.geometry("860x560")

        self.path_var = tk.StringVar(value=str(Path.cwd()))
        self.output_var = tk.StringVar(value=str(Path.cwd() / "report.html"))
        self.format_var = tk.StringVar(value="html")
        self.sast_var = tk.BooleanVar(value=True)
        self.show_values_var = tk.BooleanVar(value=False)
        self.severity_var = tk.StringVar(value="Low")
        self.max_mb_var = tk.IntVar(value=5)
        self.advice_var = tk.StringVar(value=str(Path.cwd() / "fix_guidance.txt"))

        self.status_var = tk.StringVar(value="Ready.")
        self._build()

    def _build(self):
        pad = {"padx": 10, "pady": 6}
        frm = ttk.Frame(self)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Secret Scanner GUI", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=4, sticky="w", **pad)

        ttk.Label(frm, text="Target folder:").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.path_var, width=72).grid(row=1, column=1, columnspan=2, sticky="we", **pad)
        ttk.Button(frm, text="Browse...", command=self.browse_folder).grid(row=1, column=3, sticky="e", **pad)

        ttk.Label(frm, text="Output file:").grid(row=2, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.output_var, width=72).grid(row=2, column=1, columnspan=2, sticky="we", **pad)
        ttk.Button(frm, text="Save as...", command=self.browse_output).grid(row=2, column=3, sticky="e", **pad)

        ttk.Label(frm, text="Format:").grid(row=3, column=0, sticky="w", **pad)
        ttk.Combobox(frm, textvariable=self.format_var, values=["html", "json", "csv"], width=10, state="readonly").grid(row=3, column=1, sticky="w", **pad)

        ttk.Label(frm, text="Severity threshold:").grid(row=3, column=2, sticky="e", **pad)
        ttk.Combobox(frm, textvariable=self.severity_var, values=["Critical", "High", "Medium", "Low"], width=10, state="readonly").grid(row=3, column=3, sticky="w", **pad)

        opts = ttk.LabelFrame(frm, text="Options")
        opts.grid(row=4, column=0, columnspan=4, sticky="we", **pad)
        ttk.Checkbutton(opts, text="Include SAST (regex heuristic)", variable=self.sast_var).grid(row=0, column=0, sticky="w", padx=10, pady=6)
        ttk.Checkbutton(opts, text="Show values (UNMASKED) ⚠️", variable=self.show_values_var).grid(row=0, column=1, sticky="w", padx=10, pady=6)

        ttk.Label(opts, text="Max file size (MB):").grid(row=1, column=0, sticky="w", padx=10, pady=6)
        ttk.Spinbox(opts, from_=1, to=50, textvariable=self.max_mb_var, width=6).grid(row=1, column=1, sticky="w", padx=10, pady=6)

        ttk.Label(frm, text="Fix guidance file (optional):").grid(row=5, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.advice_var, width=72).grid(row=5, column=1, columnspan=2, sticky="we", **pad)
        ttk.Button(frm, text="Save as...", command=self.browse_advice).grid(row=5, column=3, sticky="e", **pad)

        btns = ttk.Frame(frm)
        btns.grid(row=6, column=0, columnspan=4, sticky="we", **pad)
        self.scan_btn = ttk.Button(btns, text="Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=4)
        ttk.Button(btns, text="Open output", command=self.open_output).pack(side="left", padx=4)
        ttk.Button(btns, text="Open folder", command=self.open_folder).pack(side="left", padx=4)
        ttk.Button(btns, text="Quit", command=self.destroy).pack(side="right", padx=4)

        self.log = tk.Text(frm, height=12, wrap="word")
        self.log.grid(row=7, column=0, columnspan=4, sticky="nsew", padx=10, pady=6)
        self.log.insert("end", "Ready. Select a folder and click Scan.\n")
        self.log.configure(state="disabled")

        ttk.Label(frm, textvariable=self.status_var).grid(row=8, column=0, columnspan=4, sticky="w", padx=10, pady=6)

        frm.columnconfigure(1, weight=1)
        frm.columnconfigure(2, weight=1)
        frm.rowconfigure(7, weight=1)

    def browse_folder(self):
        p = filedialog.askdirectory(initialdir=self.path_var.get() or str(Path.cwd()))
        if p:
            self.path_var.set(p)

    def browse_output(self):
        ext = self.format_var.get().lower()
        filetypes = {
            "html": [("HTML report", "*.html"), ("All files", "*.*")],
            "json": [("JSON report", "*.json"), ("All files", "*.*")],
            "csv": [("CSV report", "*.csv"), ("All files", "*.*")],
        }.get(ext, [("All files", "*.*")])
        p = filedialog.asksaveasfilename(
            defaultextension=f".{ext}",
            filetypes=filetypes,
            initialdir=str(Path(self.output_var.get()).parent if self.output_var.get() else Path.cwd()),
            initialfile=f"report.{ext}",
        )
        if p:
            self.output_var.set(p)

    def browse_advice(self):
        p = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt"), ("All files", "*.*")],
            initialdir=str(Path(self.advice_var.get()).parent if self.advice_var.get() else Path.cwd()),
            initialfile="fix_guidance.txt",
        )
        if p:
            self.advice_var.set(p)

    def open_output(self):
        out = Path(self.output_var.get())
        if out.exists():
            webbrowser.open(out.as_uri())
        else:
            messagebox.showinfo("Open output", "Output file not found yet. Run Scan first.")

    def open_folder(self):
        out = Path(self.output_var.get())
        folder = out.parent if out.parent.exists() else Path.cwd()
        try:
            import os
            os.startfile(str(folder))  # Windows
        except Exception:
            webbrowser.open(folder.as_uri())

    def _append_log(self, text: str):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start_scan(self):
        target = Path(self.path_var.get())
        if not target.exists() or not target.is_dir():
            messagebox.showerror("Invalid folder", "Please choose a valid target folder.")
            return

        if self.show_values_var.get():
            ok = messagebox.askyesno(
                "Warning",
                "You enabled UNMASKED values.\n\n"
                "⚠️ This may expose real secrets in reports/logs.\n"
                "Use ONLY with fake/test data.\n\nContinue?"
            )
            if not ok:
                self.show_values_var.set(False)
                return

        self.scan_btn.config(state="disabled")
        self.status_var.set("Scanning...")
        self._append_log(f"Scanning: {target}")

        t = threading.Thread(target=self._run_scan, daemon=True)
        t.start()

    def _run_scan(self):
        try:
            target = self.path_var.get()
            scanner = Scanner(
                target,
                ignore_patterns=[],
                include_sast=self.sast_var.get(),
                max_file_size_mb=int(self.max_mb_var.get()),
            )
            findings = scanner.scan()

            # severity filtering
            min_level = SEVERITY_LEVELS.get(self.severity_var.get(), 3)
            findings = [f for f in findings if SEVERITY_LEVELS.get(f.severity, 9) <= min_level]

            out = Path(self.output_var.get())
            fmt = self.format_var.get().lower()
            show_values = self.show_values_var.get()

            if fmt == "html":
                save_html(findings, out, show_values=show_values)
            elif fmt == "json":
                save_json(findings, out, show_values=show_values)
            elif fmt == "csv":
                save_csv(findings, out, show_values=show_values)
            else:
                raise ValueError("Unknown format")

            advice_path = self.advice_var.get().strip()
            if advice_path:
                save_guidance(findings, advice_path)

            self.after(0, lambda: self._on_done(findings))
        except Exception as e:
            self.after(0, lambda: self._on_error(e))

    def _on_done(self, findings):
        self.scan_btn.config(state="normal")
        self.status_var.set(f"Done. Findings: {len(findings)}")
        self._append_log(f"Done. Findings: {len(findings)}")
        self._append_log(f"Output: {self.output_var.get()}")
        self._append_log(f"Advice: {self.advice_var.get()}")
        self._append_log("-" * 60)
        if self.format_var.get().lower() == "html" and Path(self.output_var.get()).exists():
            webbrowser.open(Path(self.output_var.get()).as_uri())

    def _on_error(self, e: Exception):
        self.scan_btn.config(state="normal")
        self.status_var.set("Error.")
        self._append_log(f"ERROR: {e}")
        messagebox.showerror("Scan error", str(e))


if __name__ == "__main__":
    app = App()
    app.mainloop()
