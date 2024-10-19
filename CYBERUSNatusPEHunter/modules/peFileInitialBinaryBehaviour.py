from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from utils.scriptDirectories import DIRECTORIES
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Union,Type
import json

def GetBinaryBehaviour(fileName:Type[str])->Union[dict,None]:
    resultLast = {}
    retriesString = GetStringBehaviour(fileName)
    foundFiles = retriesString["FOUND_FILE"]
    if len(foundFiles) > 0:
        filesList = list(foundFiles.keys())
        #filesList.append("AddinUtil.exe") #FOR TEST
        binaryCheckData = json.load(open(DIRECTORIES.BINARYCHECKSOURCE,"r"))
        for item in binaryCheckData:
            try:
                if (item["Name"].lower() in filesList) or (item["Name"] in filesList) or (item["Name"].upper() in filesList) or (item["Name"].capitalize() in filesList):
                    binaryJSON = json.loads(json.dumps(item,indent=4))
                    commands = binaryJSON["Commands"]
                    commandDict = {}
                    if len(commands) > 0:
                        for cmdInit in commands:
                            commandDict.update(
                                {
                                    "COMMAND":cmdInit["Command"],
                                    "DESCRIPTION_COMMAND":cmdInit["Description"],
                                    "USECASE":cmdInit["Usecase"],
                                    "CATEGORY":cmdInit["Category"],
                                    "PRIVILEGE_FOCUS":cmdInit["Privileges"],
                                    "MITRE_ID":cmdInit["MitreID"],
                                    "OS_FOCUS":cmdInit["OperatingSystem"]
                                }
                            )
                    else:
                        pass
                    fullPaths = binaryJSON["Full_Path"]
                    fullPathDict = {}
                    if len(fullPaths) > 0:
                        for cnt,pathInit in enumerate(fullPaths):
                            fullPathDict.update(
                                {
                                    f"PATH_{str(cnt+1)}":pathInit["Path"]
                                }
                            )
                    else:
                        pass
                    sigmaDetection = binaryJSON["Detection"]
                    sigmaDict = {}
                    if len(sigmaDetection) > 0:
                        for sgm in sigmaDetection:
                            for key,value in sgm.items():
                                sigmaDict.update(
                                    {
                                        f"SIGMA_{str(key).upper()}":value
                                    }
                                )
                    else:
                        pass
                    resultLast[item["Name"]] = {
                        "DESCRIPTION": binaryJSON["Description"],
                        "POSSIBLE_SUSPICIOUS_COMMANDS_LIST":commandDict,
                        "POSSIBLE_PATH":fullPathDict,
                        "SIGMA_DETECTION":sigmaDict
                    }
                else:
                    pass
            except Exception as err:
                ReturnInitialError(err)
        results = resultLast if len(resultLast) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO FILE SECTION FROM STRING BEHAVIOUR")
        return None