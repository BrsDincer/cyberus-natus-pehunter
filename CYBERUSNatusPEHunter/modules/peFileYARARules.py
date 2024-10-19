from utils.scriptFunctions import ReturnInitialInfo
from typing import Union,Type,Optional
import os,yara

def GetYARAFromFile(fileName:Type[str],YARAFile:Optional[str]=None)->Union[list,None]:
    # https://github.com/Yara-Rules/rules/
    yaraMatch = []
    if YARAFile is not None:
        rules = yara.compile(YARAFile)
        if rules:
            try:
                for mtc in rules.match(fileName):
                    yaraMatch.append(str(mtc))
            except Exception as err:
                print(err)
                pass
            results = yaraMatch if len(yaraMatch) > 0 else None
            return results
        else:
            ReturnInitialInfo("THERE IS NO MATCHED YARA RULE")
            return None
    else:
        ReturnInitialInfo("THERE IS NO YARA FILE")
        return None
    
def GetYARAFromFolder(fileName:Type[str],YARAFolder:Optional[str]=None,excludeList:Type[list]=[])->Union[list,None]:
    # https://github.com/Yara-Rules/rules/
    yaraMatch = []
    if YARAFolder is not None:
        for (dirPath,_,names) in os.walk(YARAFolder):
            for fs in names:
                if (str(fs).endswith(".yar")) and (str(fs) not in excludeList):
                    pathYARA = str(dirPath)+os.sep+str(fs)
                    try:
                        rules = yara.compile(pathYARA)
                        if rules:
                            for mtc in rules.match(fileName,timeout=80):
                                yaraMatch.append({str(fs):str(mtc)})
                        else:
                            pass
                    except:
                        pass
                else:
                    pass
        results = yaraMatch if len(yaraMatch) > 0 else None
        return results
    else:
        ReturnInitialInfo("THERE IS NO YARA FOLDER")
        return None


