# password_checker_gui.py
import re
import string
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

COMMON_FILE = Path("common.txt")


# ---------- strength logic ----------
def analyze_password(pw: str):
    rules = {
        "At least 8 characters": len(pw) >= 8,
        "Uppercase letter": any(c.isupper() for c in pw),
        "Lowercase letter": any(c.islower() for c in pw),
        "Number": any(c.isdigit() for c in pw),
        "Special character": any(c in string.punctuation for c in pw),
    }
    score = sum(rules.values())  # 0..5

    # common password check (It will show auto-fail message in UI, but will still show score)
    in_common = False
    if COMMON_FILE.exists():
        try:
            with open(COMMON_FILE, "r", encoding="utf-8") as f:
                common = set(line.strip() for line in f if line.strip())
            in_common = pw in common
        except Exception:
            in_common = False

    # rough entropy (very rough, just for display)
    charset = 0
    if re.search(r"[a-z]", pw):
        charset += 26
    if re.search(r"[A-Z]", pw):
        charset += 26
    if re.search(r"\d", pw):
        charset += 10
    if re.search(rf"[{re.escape(string.punctuation)}]", pw):
        charset += 32
    entropy = 0 if not pw or not charset else round(len(pw) * (charset**0.5) / 10, 1)

    return rules, score, entropy, in_common


def score_to_label(score: int):
    if score <= 2:
        return "Weak", "#e74c3c"
    if score == 3:
        return "Fair", "#f1c40f"
    if score == 4:
        return "Good", "#27ae60"
    return "Strong", "#2ecc71"


# ---------- UI handlers ----------
def update_ui(*_):
    pw = pw_var.get()
    rules, score, entropy, in_common = analyze_password(pw)

    # checklist
    for (text, ok), lbl in zip(rules.items(), rule_labels):
        lbl.configure(
            text=("✓ " if ok else "✗ ") + text, fg=("#27ae60" if ok else "#e74c3c")
        )

    # meter
    pct = score * 20
    meter["value"] = pct
    label, color = score_to_label(score)
    style.configure(
        "meter.Horizontal.TProgressbar", background=color, troughcolor="#eee"
    )
    status_var.set(
        f"Strength: {label}  |  Score: {score}/5  |  Length: {len(pw)}  |  Rough entropy: {entropy}"
    )

    # common warning
    if in_common and pw:
        common_var.set("This password appears in a common-password list.")
    else:
        common_var.set("")

    tip_var.set("")


def toggle_show():
    entry.configure(show="" if show_var.get() else "•")


def suggest():
    pw = pw_var.get()
    rules, score, *_ = analyze_password(pw)
    missing = [r for r, ok in rules.items() if not ok]
    tip_var.set(
        "Nice! Meets all rules."
        if not missing
        else "To improve, add: " + ", ".join(missing)
    )


def copy_feedback():
    text = status_var.get()
    if common_var.get():
        text += f"\n{common_var.get()}"
    text += "\n" + "\n".join(lbl.cget("text") for lbl in rule_labels)
    root.clipboard_clear()
    root.clipboard_append(text)
    messagebox.showinfo("Copied", "Summary copied to clipboard.")


# ---------- build UI ----------
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("560x420")
root.resizable(False, False)

style = ttk.Style()
style.theme_use("default")
style.configure("meter.Horizontal.TProgressbar", thickness=16)

wrap = ttk.Frame(root, padding=16)
wrap.pack(fill="both", expand=True)

ttk.Label(wrap, text="Enter Password", font=("Segoe UI", 11, "bold")).pack(anchor="w")
pw_var = tk.StringVar()
entry = ttk.Entry(wrap, textvariable=pw_var, width=48, show="•")
entry.pack(fill="x", pady=6)
pw_var.trace_add("write", update_ui)

show_var = tk.BooleanVar(value=False)
ttk.Checkbutton(
    wrap, text="Show password", variable=show_var, command=toggle_show
).pack(anchor="w")

meter = ttk.Progressbar(wrap, style="meter.Horizontal.TProgressbar", maximum=100)
meter.pack(fill="x", pady=12)

status_var = tk.StringVar(value="Strength: —")
ttk.Label(wrap, textvariable=status_var).pack(anchor="w")

common_var = tk.StringVar(value="")
ttk.Label(wrap, textvariable=common_var, foreground="#d35400").pack(anchor="w")

ttk.Label(wrap, text="Requirements", font=("Segoe UI", 10, "bold")).pack(
    anchor="w", pady=(10, 0)
)
rules_frame = ttk.Frame(wrap)
rules_frame.pack(fill="x", pady=6)

rule_labels = []
for _ in range(5):
    lbl = tk.Label(rules_frame, text="", anchor="w", font=("Segoe UI", 10))
    lbl.pack(anchor="w")
    rule_labels.append(lbl)

btns = ttk.Frame(wrap)
btns.pack(fill="x", pady=(10, 0))
ttk.Button(btns, text="Suggest improvements", command=suggest).pack(side="left")
ttk.Button(btns, text="Copy summary", command=copy_feedback).pack(side="left", padx=8)

tip_var = tk.StringVar(value="")
ttk.Label(wrap, textvariable=tip_var, wraplength=520, foreground="#555").pack(
    anchor="w", pady=(8, 0)
)

entry.focus()
update_ui()
root.mainloop()
