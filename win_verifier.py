# -*- coding: utf-8 -*-
import ctypes
import os
from ctypes import wintypes





# ================= DEFINIÇÕES DA API DO WINDOWS =================

wintrust = ctypes.windll.wintrust
WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"

class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_ulong),
                ("Data2", ctypes.c_ushort),
                ("Data3", ctypes.c_ushort),
                ("Data4", ctypes.c_ubyte * 8)]
    
class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_ulong),
                ("pcwszFilePath", ctypes.c_wchar_p),
                ("hFile", ctypes.c_void_p),
                ("pgKnownSubject", ctypes.c_void_p)]
    
class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cbStruct", ctypes.c_ulong),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", ctypes.c_ulong),
                ("fdwRevocationChecks", ctypes.c_ulong),
                ("dwUnionChoice", ctypes.c_ulong),
                ("pFile", ctypes.c_void_p),
                ("dwStateAction", ctypes.c_ulong),
                ("hWVTStateData", ctypes.c_void_p),
                ("pwszURLReference", ctypes.c_wchar_p),
                ("dwProvFlags", ctypes.c_ulong),
                ("dwUIContext", ctypes.c_ulong),
                ("pSignatureSettings", ctypes.c_void_p)]
    

def verify_signature(path: str) -> bool:

    """
    Verifica se o ficheiro tem uma assinatura digital válida (Microsoft, etc.)
    Usa a API WinVerifyTrust (muito rápido).
    """
    if not os.path.exists(path):
        return False
    

    # Configurar estruturas
    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    trust_data.dwUIChoice = 2  # Sem UI
    trust_data.fdwRevocationChecks = 0 # Sem check online pesado
    trust_data.dwUnionChoice = 1  # Ficheiro
    trust_data.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
    trust_data.dwStateAction = 0 
    trust_data.dwProvFlags = 0x00000010 | 0x00000080 # Cache only

    action_guid = GUID()
    ctypes.windll.ole32.CLSIDFromString(WINTRUST_ACTION_GENERIC_VERIFY_V2, ctypes.byref(action_guid))
    

    try:
        result = wintrust.WinVerifyTrust(None, ctypes.byref(action_guid), ctypes.byref(trust_data))
        return result == 0
    
    except Exception:
        return False