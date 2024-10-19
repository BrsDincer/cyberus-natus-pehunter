from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialInfo
from typing import Union,Type

def GetDLLList(peRaw:Type[I_Class])->Union[dict,None]:
    dllDict = {}
    dllDict["DLL_LIST"] = []
    if hasattr(peRaw,"DIRECTORY_ENTRY_IMPORT"):
        for lib in peRaw.DIRECTORY_ENTRY_IMPORT:
            try:
                try:
                    dll = lib.dll.decode("utf-8","ignore").strip()
                except:
                    dll = lib.dll.decode("latin1","ignore").strip()
                if dll not in dllDict["DLL_LIST"]:
                    dllDict["DLL_LIST"].append(dll)
                else:
                    pass
            except:
                pass
        results = dllDict if len(dllDict["DLL_LIST"]) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO ENTRY IMPORT INFORMATION")
        return None