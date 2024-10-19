from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialInfo
from utils.scriptDirectories import DIRECTORIES
from modules.peFileSuspiciousImports import GetSuspiciousImports
from typing import Union,Type
import json

def GetCapabilities(peRaw:Type[I_Class])->Union[dict,None]:
    # https://github.com/mandiant/capa-rules/
    retriesCapabilities = {}
    retriesSuspiciousImports = GetSuspiciousImports(peRaw)
    if len(retriesSuspiciousImports) > 0:
        susImports = list(retriesSuspiciousImports.keys())
        capabilitiesImports = json.load(open(DIRECTORIES.CAPABILITIESSOURCE,"r"))
        capabilitiesImportsValues = list(capabilitiesImports.values())
        for imp in susImports:
            try:
                for capa in capabilitiesImportsValues:
                    listAPI = capa["API_LIST"]
                    if imp in listAPI:
                        retriesCapabilities[imp] = {
                            "CAPABILITY_NAME":capa["NAME"].capitalize(),
                            "ATTCK_CODE":capa["ATTCK"],
                            "MBC_CODE":capa["MBC"]
                        }
                    else:
                        pass
            except:
                pass
        results = retriesCapabilities if len(retriesCapabilities) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO SUSPICIOUS IMPORTS")
        return None