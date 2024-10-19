from utils.scriptUtilization import I_Class
from utils.scriptFunctions import LoadJSONConfiguration,ReturnInitialInfo,ReturnInitialError
from typing import Type,Union

def GetSuspiciousImports(peRaw:Type[I_Class])->Union[dict,None]:
    alertImports = {}
    suspiciousBreakpoints = LoadJSONConfiguration()["breakpoint"]
    suspiciousMutex = LoadJSONConfiguration()["mutex"]
    suspiciousAntiDebug = LoadJSONConfiguration()["antidbg"]
    if hasattr(peRaw,"DIRECTORY_ENTRY_IMPORT"):
        try:
            for library in peRaw.DIRECTORY_ENTRY_IMPORT:
                targetDLL = library.dll
                for imp in library.imports:
                    if imp.name is not None:
                        if (imp.name.decode("ascii").rstrip() != ""):
                            if imp.name.decode("ascii").rstrip() in suspiciousBreakpoints:
                                alertImports[imp.name.decode("ascii").rstrip()] = {
                                    "SUSPICIOUS_TYPE":"BREAKPOINT",
                                    "DLL":targetDLL.decode("utf-8").rstrip(),
                                    "ADDRESS_NOR":imp.address,
                                    "ADDRESS_HEX":hex(imp.address),
                                    "ORDINAL":imp.ordinal,
                                    "ORDINAL_OFFSET":imp.ordinal_offset
                                }
                            elif imp.name.decode("ascii").rstrip() in suspiciousMutex:
                                alertImports[imp.name.decode("ascii").rstrip()] = {
                                    "SUSPICIOUS_TYPE":"MUTEX",
                                    "DLL":targetDLL.decode("utf-8").rstrip(),
                                    "ADDRESS_NOR":imp.address,
                                    "ADDRESS_HEX":hex(imp.address),
                                    "ORDINAL":imp.ordinal,
                                    "ORDINAL_OFFSET":imp.ordinal_offset
                                }
                            elif imp.name.decode("ascii").rstrip() in suspiciousAntiDebug:
                                alertImports[imp.name.decode("ascii").rstrip()] = {
                                    "SUSPICIOUS_TYPE":"ANTI_DEBUG",
                                    "DLL":targetDLL.decode("utf-8").rstrip(),
                                    "ADDRESS_NOR":imp.address,
                                    "ADDRESS_HEX":hex(imp.address),
                                    "ORDINAL":imp.ordinal,
                                    "ORDINAL_OFFSET":imp.ordinal_offset
                                }
                            else:
                                pass
                        else:
                            pass
                    else:
                        pass
        except Exception as err:
            ReturnInitialError(err)
        results = alertImports if len(alertImports) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO ENTRY IMPORT INFORMATION")
        return None