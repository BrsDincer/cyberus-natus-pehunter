from utils.scriptUtilization import I_Class
from utils.scriptFunctions import LoadJSONConfiguration,ReturnInitialInfo,ReturnInitialError
from typing import Type,Union

def GetNormalImports(peRaw:Type[I_Class])->Union[dict,None]:
    normalImports = {}
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
                            if (imp.name.decode("ascii").rstrip() not in suspiciousBreakpoints) and (imp.name.decode("ascii").rstrip() not in suspiciousMutex) and (imp.name.decode("ascii").rstrip() not in suspiciousAntiDebug):
                                normalImports[imp.name.decode("ascii").rstrip()] = {
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
        results = normalImports if len(normalImports) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO ENTRY IMPORT INFORMATION")
        return None