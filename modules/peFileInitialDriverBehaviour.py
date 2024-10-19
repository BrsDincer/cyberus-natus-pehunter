from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from utils.scriptDirectories import DIRECTORIES
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Union,Type
import json

def GetDriverBehaviour(fileName:Type[str])->Union[dict,None]:
    resultLast = {}
    retriesString = GetStringBehaviour(fileName)
    foundFiles = retriesString["FOUND_FILE"]
    if len(foundFiles) > 0:
        filesList = list(foundFiles.keys())
        #filesList.append("BSMIx64.sys") #FOR TEST
        driverCheckData = json.load(open(DIRECTORIES.DRIVERCHECKSOURCE,"r",encoding="utf-8",errors="ignore"))
        for cnt,item in enumerate(driverCheckData):
            tagsData = item["Tags"]
            if len(tagsData) > 0:
                if any(str(tag).lower() in tagsData for tag in filesList) or any(str(tag).upper() in tagsData for tag in filesList) or any(str(tag).capitalize() in tagsData for tag in filesList) or any(tag in tagsData for tag in filesList):
                    initialDict = {}
                    commands = item["Commands"]
                    commandDict = {}
                    if len(commands) > 0:
                        commandDict.update(
                            {
                                "COMMAND":commands["Command"],
                                "DESCRIPTION":commands["Description"],
                                "OS_FOCUS":commands["OperatingSystem"],
                                "PRIVILEGE_FOCUS":commands["Privileges"],
                                "USECASE":commands["Usecase"]
                            }
                        )
                    else:
                        pass
                    resources = item["Resources"]
                    resourceDict = {}
                    if len(resources) > 0:
                        resourceDict.update(
                            {
                                "RESOURCES":",".join(resources)
                            }
                        )
                    else:
                        pass
                    detections = item["Detection"]
                    detectionDict = {}
                    if len(detections) > 0:
                        for cnt,det in enumerate(detections):
                            for _,value in det.items():
                                detectionDict[f"DETECTION_{str(cnt+1)}"] = value
                    else:
                        pass
                    vulnerableSection = item["KnownVulnerableSamples"]
                    vulnerableDict = {}
                    if len(vulnerableSection) > 0:
                        for cnt,det in enumerate(vulnerableSection):
                            if isinstance(det,dict):
                                companyName = det["Company"]
                                copywrite = det["Copyright"]
                                timeStamp = det["CreationTimestamp"]
                                descriptionVuln = det["Description"]
                                exportedFunc = ", ".join(det["ExportedFunctions"]) if isinstance(det["ExportedFunctions"],list) else det["ExportedFunctions"]
                                importedFunc = ", ".join(det["ImportedFunctions"]) if isinstance(det["ImportedFunctions"],list) else det["ImportedFunctions"]
                                imports = ", ".join(det["Imports"]) if isinstance(det["Imports"],list) else det["Imports"]
                                fileVersion = det["FileVersion"]
                                magicHeader = det["MagicHeader"]
                                machineType = det["MachineType"]
                                md5Vuln = det["MD5"]
                                secVuln = det["Sections"]
                                if len(secVuln) > 0:
                                    if isinstance(secVuln,dict):
                                        initialsecDict = {}
                                        for sKey,sVal in secVuln.items():
                                            initialsecDict[str(sKey)] = {
                                                "ENTROPY":sVal["Entropy"],
                                                "VIRTUAL_SIZE":sVal["Virtual Size"]
                                                }
                                    else:
                                        pass
                                else:
                                    pass
                                signVuln = ", ".join(det["Signature"]) if isinstance(det["Signature"],list) else det["Signature"]
                                vulnerableDict[f"BASE_INFO_{str(cnt+1)}"] = {
                                    "COMPANY_NAME":companyName,
                                    "COPYWRITE":copywrite,
                                    "TIMESTAMP":timeStamp,
                                    "DESCRIPTION":descriptionVuln,
                                    "EXPORTED_FUNCTIONS":exportedFunc,
                                    "IMPORTED_FUNCTIONS":importedFunc,
                                    "IMPORTS":imports,
                                    "FILE_VERSION":fileVersion,
                                    "MAGIC_HEADER":magicHeader,
                                    "MACHINE_FOCUS":machineType,
                                    "MD5_HASH":md5Vuln,
                                    "SECTION_INFO":initialsecDict,
                                    "SIGNATURES":signVuln
                                }
                            else:
                                pass
                    else:
                        pass
                    try:
                        initialDict.update(
                            {
                                "VERIFIED":item["Verified"],
                                "MITRE_ID":item["MitreID"],
                                "CATEGORY":item["Category"],
                                "RESOURCES":resourceDict,
                                "COMMANDS":commandDict,
                                "DETECTIONS":detectionDict,
                                "INFORMATIONS":vulnerableDict
                            }
                        )
                    except Exception as err:
                        ReturnInitialError(err)
                    resultLast[str(cnt+1)] = {
                        "DETAILS":initialDict
                    }
                else:
                    pass
            else:
                pass
        results = resultLast if len(resultLast) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO FILE SECTION FROM STRING BEHAVIOUR")
        return None