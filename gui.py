# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter import simpledialog
import threading
import queue
import os
import re
import integrity_monitor
import subprocess

# ================= CONFIG =================
MAX_GUI_LOG_LINES = 1000
PATH_REGEX = re.compile(r'("?[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+"?)')
LOG_COLORS = {
    "INFO": "blue",
    "WARNING": "orange",
    "ERROR": "red",
    "SECURITY": "purple",
    "DEFAULT": "black"
}

# ================= GUI =================
root = tk.Tk()
root.title("Integrity Monitor")
root.geometry("800x600")

log_queue = queue.Queue()
log_text = scrolledtext.ScrolledText(root, width=100, height=30)
log_text.config(state="disabled")
log_text.pack(pady=10)

# ================= LOG =================
def log(event: dict):
    log_queue.put(event)

# ================= FILE OPEN =================
def _get_path_from_line(line: str):
    match = PATH_REGEX.search(line)
    if match:
        return match.group(0).strip('"')
    return None

def open_file_from_log(event):
    index = log_text.index(f"@{event.x},{event.y}")
    line = log_text.get(f"{index} linestart", f"{index} lineend")
    path = _get_path_from_line(line)

    if path and os.path.exists(path):

        subprocess.run(f'explorer /select,"{path}"')

# ================= CURSOR CONTROL =================
def on_motion(event):
    index = log_text.index(f"@{event.x},{event.y}")
    line = log_text.get(f"{index} linestart", f"{index} lineend")
    if _get_path_from_line(line):
        log_text.config(cursor="hand2")
    else:
        log_text.config(cursor="")

log_text.bind("<Motion>", on_motion)
log_text.bind("<Double-Button-1>", open_file_from_log)

# ================= PROCESSAMENTO =================
def _trim_logs():
    lines = int(log_text.index("end-1c").split(".")[0])
    if lines > MAX_GUI_LOG_LINES:
        log_text.delete("1.0", f"{lines - MAX_GUI_LOG_LINES}.0")

def process_log_queue():
    while not log_queue.empty():
        event = log_queue.get()
        level = event.get("level", "DEFAULT")
        message = event.get("message", "")

        if level == "INFO_POPUP":
            messagebox.showinfo("Info", message)
            continue
        
        if level == "ERROR_POPUP":
            messagebox.showerror("Erro", message)
            continue
        
        log_text.config(state="normal")
        log_text.insert(tk.END, message + "\n", level)
        log_text.tag_config(level, foreground=LOG_COLORS.get(level, "black"))
        log_text.see(tk.END)

        _trim_logs()

        log_text.config(state="disabled")

    root.after(100, process_log_queue)

# ================= WORKERS =================
def create_baseline_worker(password):
    try:
        log({"level": "INFO", "message": "[*] Criar baseline"})
        integrity_monitor.create_and_save_baseline(password)
        log({"level": "INFO_POPUP", "message": "Baseline criada e assinada com sucesso"})
    except Exception as e:
        log({"level": "ERROR_POPUP", "message": str(e)})

def check_integrity_worker(password):
    try:
        log({"level": "INFO", "message": "[*] Verificação iniciada"})
        alerts = integrity_monitor.check_integrity(password)

        if any("Password errada" in x["message"] for x in alerts.get("SECURITY", [])):
            log({"level": "ERROR", "message": "ERRO: A password introduzida não corresponde à assinatura da Baseline."})
        
        for level, items in alerts.items():
            for msg in items:
                log(msg)
                
        log({"level": "INFO_POPUP", "message": "Verificação concluída"})

        log_path = integrity_monitor._log_path(0)
        log({"level": "INFO", "message": f"Log detalhado guardado em: {log_path}"})

    except Exception as e:
        log({"level": "ERROR_POPUP", "message": str(e)})



# ================= FUNÇÕES DE BOTÃO =================

def on_click_create():
    pwd = simpledialog.askstring("Segurança", "Define uma Password para proteger a Baseline:", show='*')
    if pwd:
        threading.Thread(target=create_baseline_worker, args=(pwd,), daemon=True).start()

def on_click_check():
    pwd = simpledialog.askstring("Segurança", "Insere a Password da Baseline:", show='*')
    if pwd:
        threading.Thread(target=check_integrity_worker, args=(pwd,), daemon=True).start()


# ================= BOTÕES =================

frame = tk.Frame(root)
frame.pack(pady=10)

tk.Button(frame, text="Criar Baseline", width=20, command=on_click_create).pack(side=tk.LEFT, padx=5)
tk.Button(frame, text="Verificar Integridade", width=20, command=on_click_check).pack(side=tk.LEFT, padx=5)

process_log_queue()
root.mainloop()
