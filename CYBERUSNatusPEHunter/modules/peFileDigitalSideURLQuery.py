from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo,DeleteHTTPTag
from utils.scriptDirectories import DIRECTORIES
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Union,Type
import json

def GetDigitalSideURL(fileName:Type[str])->Union[dict,None]:
    resultLast = {}
    retriesString = GetStringBehaviour(fileName)
    foundServices = retriesString["FOUND_SERVICE"]
    #foundServices.append("proxy.amazonscouts.com") # FOR TEST
    countDict = 0
    if len(foundServices) > 0:
        maliciousURLs = json.load(open(DIRECTORIES.DIGITALSIDEURLSOURCE,"r"))
        objectURLs = maliciousURLs["objects"][1:]
        try:
            for obj in objectURLs:
                targetPattern = obj.get("pattern",None)
                if targetPattern:
                    for srv in foundServices:
                        cleanSrv = DeleteHTTPTag(str(srv))
                        if "/" in cleanSrv:
                            cleanSrv = cleanSrv.split("/")[0]
                        else:
                            pass
                        if cleanSrv in targetPattern:
                            countDict += 1
                            iocID = obj["id"]
                            iocReference = obj["created_by_ref"]
                            iocType = ", ".join(obj["indicator_types"]) if len(obj["indicator_types"]) > 0 else "NONE"
                            patternType = obj["pattern_type"]
                            createDate = obj["created"]
                            name = obj["name"]
                            description = obj["description"]
                            validFrom = obj["valid_from"]
                            validUntil = obj["valid_until"]
                            killChain = obj["kill_chain_phases"]
                            if killChain:
                                if len(killChain) > 0:
                                    killChainDict = {}
                                    for idx in killChain:
                                        if isinstance(idx,dict):
                                            for key,value in idx.items():
                                                killChainDict[str(key).upper()] = value
                                        else:
                                            pass
                                else:
                                    pass
                            else:
                                pass
                            resultLast[countDict] = {
                                "NAME":name,
                                "DESCRIPTION":description,
                                "VALID_FROM":validFrom,
                                "VALID_TO":validUntil,
                                "IOC_ID":iocID,
                                "IOC_REFERENCE":iocReference,
                                "IOC_TYPE":iocType,
                                "PATTERN":targetPattern,
                                "PATTERN_TYPE":patternType,
                                "PATTERN_CLEAR":cleanSrv,
                                "CREATE_DATE":createDate,
                                "KILL_CHAIN_INFORMATION":killChainDict
                            }
                        else:
                            pass
                else:
                    pass
        except Exception as err:
            ReturnInitialError(err)
        results = resultLast if len(resultLast) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO URL FROM STRING BEHAVIOUR")
        return None