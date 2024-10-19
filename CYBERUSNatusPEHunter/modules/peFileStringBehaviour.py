from utils.scriptFunctions import FindServiceName,FindIPEntry,FindFileEntry,ReturnInitialError,TranslateApproveCharacter,CheckValidIPInput,LoadJSONConfiguration
from typing import Type,Union
import re

def GetStringBehaviour(fileName:Type[str])->Union[dict,None]:
    retries = {}
    stringList = []
    ipList = []
    fileList = []
    serviceList = []
    fileTypeDict = {}
    fuzzingDict = {}
    fileTypes = LoadJSONConfiguration()["filetype"].items()
    fuzzingTypes = LoadJSONConfiguration()["fuzzing"].items()
    stringList = list(TranslateApproveCharacter(fileName))
    #FOR STRING ANALYSIS
    try:
        for initial in stringList:
            if len(initial) < 2000:
                services = FindServiceName(initial)
                if services:
                    for service in services:
                        serviceList.append(re.sub(r"\(|\)|;|,|\$","",service[0]))
                else:
                    pass
                ips = FindIPEntry(initial)
                if ips:
                    for ip in ips:
                        if CheckValidIPInput(str(ip)) and (not re.findall(r"[0-9]{1,}\.[0-9]{1,}\.[0-9]{1,}\.0",str(ip))):
                            ipList.append(str(ip))
                        else:
                            pass
                else:
                    pass
                files = FindFileEntry(initial)
                if files:
                    for wr in files:
                        fileList.append(wr[0])
                else:
                    pass
            else:
                pass
        ipList = list(set([itm for itm in ipList]))
        serviceList = list(set([itm for itm in serviceList]))
    except Exception as err:
        ReturnInitialError(err)
    #VALID FILENAMES
    try:
        arrayTemplates = []
        for fls in fileList:
            for key,value in fileTypes:
                for ex in value:
                    matches = re.findall("\\"+ex+"$", str(fls), re.IGNORECASE | re.MULTILINE)
                    if matches and (fls.lower() not in arrayTemplates) and (len(fls) > 4):
                        fileTypeDict.update(
                            {
                                fls:key
                            }
                        )
                    else:
                        pass
    except Exception as err:
        ReturnInitialError(err)
    #FUZZING INITIALIZING
    try:
        for key,value in fuzzingTypes:
            fuzzingDict[key] = []
    except Exception as err:
        ReturnInitialError(err)
    #STRING ANALYSIS WITH FUZZING
    try:
        arrayTemplates = []
        for initial in stringList:
            if len(initial) < 256:
                for key,value in fuzzingTypes:
                    fuzzMatch = re.findall(value,initial,re.IGNORECASE|re.MULTILINE)
                    if fuzzMatch and (initial.lower() not in arrayTemplates):
                        fuzzingDict[key].append(initial)
                        arrayTemplates.append(initial.lower())
    except Exception as err:
        ReturnInitialError(err)
    #CLEANING FUZZING DICT
    try:
        for key,value in fuzzingTypes:
            if not fuzzingDict[key]:
                del fuzzingDict[key]
    except Exception as err:
        ReturnInitialError(err)
    retries.update(
        {
            "FOUND_FILE":fileTypeDict,
            "FOUND_SERVICE":serviceList,
            "FOUND_IP":ipList,
            "FOUND_FUZZING":fuzzingDict,
            "RESULT_DUMP":stringList
        }
    )
    return retries







