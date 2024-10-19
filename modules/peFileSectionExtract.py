from utils.scriptUtilization import I_Class
from utils.scriptDirectories import DIRECTORIES
from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo,CreateDirectory
from typing import Type,Union
import os

def GetExtractSection(peRaw:Type[I_Class],sectionName:Type[str]="all")->Union[bool,None]:
    isOK = False
    if os.path.exists(DIRECTORIES.SECTIONPATH):
        pass
    else:
        CreateDirectory(DIRECTORIES.SECTIONPATH)
    for sct in peRaw.sections:
        try:
            try:
                name = sct.Name.decode("utf-8","ignore").strip().replace("\00","").replace(".","")
            except:
                name = sct.Name.decode("latin1","ignore").strip().replace("\00","").replace(".","")
            dataRaw = sct.get_data()
            if str(sectionName).lower() == "all":
                if (dataRaw is not None) and (dataRaw != b" "):
                    outputDir = os.path.join(DIRECTORIES.SECTIONPATH,f"{name}_section.bin")
                    with open(outputDir,"wb") as wops:
                        wops.write(dataRaw)
                    ReturnInitialInfo(f"SECTION HAS BEEN EXTRACTED TO {outputDir}")
                    isOK = True
                else:
                    pass
            elif str(sectionName).lower() == name.lower():
                if (dataRaw is not None) and (dataRaw != b" "):
                    outputDir = os.path.join(DIRECTORIES.SECTIONPATH,f"{name}_section.bin")
                    with open(outputDir,"wb") as wops:
                        wops.write(dataRaw)
                    ReturnInitialInfo(f"SECTION HAS BEEN EXTRACTED TO {outputDir}")
                    isOK = True
                else:
                    pass
            else:
                pass
        except Exception as err:
            ReturnInitialError(err)
    return isOK



