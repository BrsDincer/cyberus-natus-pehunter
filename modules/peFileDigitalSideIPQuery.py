from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from utils.scriptDirectories import DIRECTORIES
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Union,Type
import json

def GetDigitalSideIP(fileName:Type[str])->Union[dict,None]:
    resultLast = {}
    retriesString = GetStringBehaviour(fileName)
    foundIPs = retriesString["FOUND_IP"]
    #foundIPs.append("101.108.146.126") # FOR TEST
    countDict = 0
    if len(foundIPs) > 0:
        try:
            maliciousIPs = json.load(open(DIRECTORIES.DIGITALSIDEIPSOURCE,"r"))
            for _,idx in enumerate(foundIPs):
                if str(idx).strip() in maliciousIPs:
                    countDict += 1
                    resultLast[countDict] = {
                        "POTENTIAL_MALICIOUS_IP":str(idx).strip()
                    }
                else:
                    pass
        except Exception as err:
            ReturnInitialError(err)
        results = resultLast if len(resultLast) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO IP FROM STRING BEHAVIOUR")
        return None