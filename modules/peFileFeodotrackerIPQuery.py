from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from utils.scriptDirectories import DIRECTORIES
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Type,Union
import json

def GetFeodoTrackerIP(fileName:Type[str])->Union[dict,None]:
    resultLast = {}
    retriesString = GetStringBehaviour(fileName)
    foundIPs = retriesString["FOUND_IP"]
    #foundIPs.append("1.161.100.47") #FOR TEST
    countDict = 0
    if len(foundIPs) > 0:
        try:
            botnetIPs = json.load(open(DIRECTORIES.FEODOTRACKERSOURCE,"r"))
            for _,idx in enumerate(foundIPs):
                if str(idx).strip() in botnetIPs["IPs"]:
                    countDict += 1
                    resultLast[countDict] = {
                        "POTENTIAL_BOTNET_C2_IP":str(idx).strip()
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