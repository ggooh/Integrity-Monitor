import hashlib
import json
import os
from datetime import datetime
import subprocess
import getpass
import hmac #pass digital
from win_verifier import verify_signature
import stat


# ================= CONFIGURAÇÃO =================
SECURE_FOLDER = r"C:\ProgramData\IntegrityMonitor"
BASELINE_FILE = os.path.join(SECURE_FOLDER, "baseline.json")
BASELINE_HASH_FILE = BASELINE_FILE + ".hash"
LOG_FILE_BASE = "integrity_log"
MAX_LOG_SIZE_MB = 5
MAX_LOG_FILES = 5

CRITICAL_PATHS = [
    r"C:\Windows\System32",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\teste"
]

EXCLUDED_PATHS = [
    r"\winevt\Logs",
    r"\LogFiles",
    r"\sru",
    r"\WDI\LogFiles",
    r"\AppData\Local\Temp",
    r"\Windows\Temp",
    r"\Prefetch",       
    r"\Servicing",      
    r"\SoftwareDistribution", 
    ".log",             
    ".tmp"              
]

CRITICAL_EXTENSIONS = [".exe", ".dll", ".sys", ".ps1", ".bat", ".cmd"]

# ================= UTILITÁRIOS =================

    
def is_excluded(path: str) -> bool:
    path_lower = path.lower()
    for x in EXCLUDED_PATHS:
        x_lower = x.lower()

        if x_lower.startswith("."):
            if path_lower.endswith(x_lower):
                return True
            
        elif x_lower in path_lower:
            return True
        
        return False



def is_critical(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in CRITICAL_EXTENSIONS



def calculate_hash(path: str) -> str:
    sha256 = hashlib.sha256()
    try:

        with open(path, "rb") as f:
            for block in iter(lambda: f.read(8192), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except PermissionError:
        return "ACCESS_DENIED"
    except Exception:
        return "ERROR"



def file_info(path: str) -> dict:
    stat = os.stat(path)
    return {
        "hash": calculate_hash(path),
        "size": stat.st_size,
        "mtime": stat.st_mtime
    }

# ================= PASTA SEGURA =================

def ensure_secure_folder():
    if not os.path.exists(SECURE_FOLDER):
        os.makedirs(SECURE_FOLDER)
    _apply_acl()

def _apply_acl():
    user = getpass.getuser()
    subprocess.run(
        f'icacls "{SECURE_FOLDER}" /inheritance:r /grant:r {user}:(OI)(CI)F',
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def acl_is_secure() -> bool:
    # Apenas verifica se o utilizador atual tem full control
    try:
        result = subprocess.check_output(
            f'icacls "{SECURE_FOLDER}"',
            shell=True,
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        user = getpass.getuser()
        return user in result and "(F)" in result
    except:
        return False

# ================= LOG ROTATIVO =================

def _log_path(index: int) -> str:
    if index == 0:
        return os.path.join(SECURE_FOLDER, f"{LOG_FILE_BASE}.txt")
    return os.path.join(SECURE_FOLDER, f"{LOG_FILE_BASE}_{index}.txt")


def set_file_writable(path: str, writable: bool):
    if not os.path.exists(path): return
    
    user = getpass.getuser()
    # subprocess.DEVNULL para não aparecerem janelas pretas
    kwargs = {'shell': True, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
    
    if writable:
        # Dá permissão Total (F) para o Python poder escrever/apagar
        subprocess.run(f'icacls "{path}" /grant:r "{user}":F', **kwargs)
    else:
        # Remove heranças e dá APENAS Leitura (R). O VS Code não consegue passar isto.
        subprocess.run(f'icacls "{path}" /inheritance:r /grant:r "{user}":R', **kwargs)



def _write(path, timestamp, message):
    try:
        #Destrancar para poder escrever
        set_file_writable(path, True)
        
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")
            
    finally:
        #TRANCAR (Read-Only) 
        set_file_writable(path, False)



def write_log(message: str):
    try:
        ensure_secure_folder()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        #Tentar escrever no log atual
        current_log = _log_path(0)
        
        #Se não existe ou ainda tem espaço, escreve e sai
        if not os.path.exists(current_log) or os.path.getsize(current_log) < MAX_LOG_SIZE_MB * 1024 * 1024:
            _write(current_log, timestamp, message)
            return

        #Se estiver cheio, faz a rotação
        if os.path.exists(_log_path(MAX_LOG_FILES - 1)):
            set_file_writable(_log_path(MAX_LOG_FILES - 1), True)
            os.remove(_log_path(MAX_LOG_FILES - 1)) # Apaga o mais antigo

        for i in range(MAX_LOG_FILES - 1, 0, -1):
            old = _log_path(i - 1)
            new = _log_path(i)

            if os.path.exists(old):
                set_file_writable(old, True)

                if os.path.exists(new): 
                    set_file_writable(new, True)
                    os.remove(new)

                os.rename(old, new)
                set_file_writable(new, False)
        
        #Cria um novo log 0 limpo
        _write(_log_path(0), timestamp, message)

    except Exception as e:
        print(f"Erro no Log: {e}")
# ================= BASELINE =================

def create_baseline() -> dict:
    baseline = {}
    write_log("[*] Criação da baseline iniciada")
    for base in CRITICAL_PATHS:
        for root, _, files in os.walk(base):
            for f in files:
                path = os.path.join(root, f)
                if is_excluded(path) or not is_critical(path):
                    continue
                try:
                    baseline[path] = file_info(path)
                except Exception:
                    pass
    write_log("[✓] Baseline criada")
    return baseline




def save_baseline(baseline: dict, password: str):
    ensure_secure_folder()
    data = {"created_at": str(datetime.now()), "files": baseline}
    
    json_text = json.dumps(data, indent=4, sort_keys=True)
    
    try:
        set_file_writable(BASELINE_FILE, True) # Destranca
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            f.write(json_text)
    finally:
        set_file_writable(BASELINE_FILE, False) # Tranca
    

    msg = json_text.encode()
    key = password.encode()
    signature = hmac.new(key, msg, hashlib.sha256).hexdigest()
    
    
    try:
        set_file_writable(BASELINE_HASH_FILE, True) # Destranca
        with open(BASELINE_HASH_FILE, "w") as f:
            f.write(signature)
    finally:
        set_file_writable(BASELINE_HASH_FILE, False) # Tranca
    
    write_log("[✓] Baseline assinada e protegida com HMAC")




def baseline_is_valid(password: str) -> bool:
    if not os.path.exists(BASELINE_FILE) or not os.path.exists(BASELINE_HASH_FILE):
        return False
    
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            content = f.read()

        with open(BASELINE_HASH_FILE, "r", encoding="utf-8") as f:
            stored_signature = f.read().strip()

        msg = content.encode()
        key = password.encode()
        calculated_signature = hmac.new(key, msg, hashlib.sha256).hexdigest()


        return hmac.compare_digest(calculated_signature, stored_signature)
    except Exception as e:
        write_log(f"[ERRO] Validar baseline: {e}")
        return False




def create_and_save_baseline(password: str):
    baseline_exists = os.path.exists(BASELINE_FILE) and os.path.exists(BASELINE_HASH_FILE)

    if baseline_exists:
        write_log("[!] Tentativa de atualizar Baseline existente...")
        

        if not baseline_is_valid(password):
            error_msg = "ACESSO NEGADO: Password incorreta. Para sobrescrever a baseline, tens de usar a password original."
            write_log(f"[SEGURANÇA] {error_msg}")    
            raise Exception(error_msg)
        
        write_log("[✓] Password correta. A iniciar atualização...")
    else:
        
        write_log("[*] Baseline inexistente. A iniciar criação de nova baseline...")

    
    baseline = create_baseline()
    save_baseline(baseline, password)



# ================= VERIFICAÇÃO =================


def check_integrity(password: str):
    alerts = {"SECURITY": [], "WARNING": [], "ERROR": []}

    # Log de início
    write_log("[*] Verificação de integridade iniciada")

    if not acl_is_secure():
        msg = "[SECURITY] ACL da pasta foi alterada"
        write_log(msg) 
        alerts["SECURITY"].append({"level": "SECURITY", "message": msg})

    if not baseline_is_valid(password):
        msg = "[CRÍTICO] Baseline inválida ou Password errada! Verificação abortada."
        write_log(msg) 
        alerts["SECURITY"].append({"level": "SECURITY", "message": msg})
        return alerts

    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        baseline = json.load(f)["files"]

    seen = set()

    for base in CRITICAL_PATHS:
        for root, _, files in os.walk(base):
            for f in files:
                path = os.path.join(root, f)
                
                if is_excluded(path) or not is_critical(path):
                    continue
                
                seen.add(path)
                
                if path not in baseline:
                    msg = f"[NOVO] {path}"
                    write_log(msg) 
                    alerts["SECURITY"].append({"level": "SECURITY", "message": msg})
                    continue
                
                try:
                    saved = baseline[path]
                    stat = os.stat(path)
                    
                    if stat.st_size != saved["size"] or stat.st_mtime != saved["mtime"]:
                        current_hash = calculate_hash(path)
                        
                        if current_hash != saved["hash"] and current_hash != "ACCESS_DENIED":
                            
                            is_signed = verify_signature(path)

                            if is_signed:
                                msg = f"[UPDATE] {path} (Assinatura Válida detectada)"
                                write_log(msg) 
                                alerts["WARNING"].append({
                                    "level": "WARNING",
                                    "message": msg
                                })
                            else:
                                msg = f"[MODIFICADO] {path} (SEM ASSINATURA VÁLIDA!)"
                                write_log(msg) 
                                alerts["SECURITY"].append({
                                    "level": "SECURITY", 
                                    "message": msg
                                })
                except Exception as e:
                    msg = f"[ERRO] {path} → {e}"
                    write_log(msg) 
                    alerts["ERROR"].append({"level": "ERROR", "message": msg})

    # Ficheiros removidos
    for path in baseline:
        if path not in seen:
            msg = f"[FALTA] {path}"
            write_log(msg) #
            alerts["WARNING"].append({"level": "WARNING", "message": msg})

    write_log("[*] Verificação concluída")
    return alerts