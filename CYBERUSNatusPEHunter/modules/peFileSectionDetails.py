from utils.scriptUtilization import I_Class
from utils.scriptFunctions import CalculateEntropy,CheckIsExecutable,ReturnInitialError
from utils.scriptConstants import SECTION_MEANS
from typing import Type,Union

def GetSectionDetails(peRaw:Type[I_Class])->Union[dict,None]:
    sectionsInfo = {}
    try:
        if hasattr(peRaw,"FILE_HEADER"):
            if hasattr(peRaw.FILE_HEADER,"NumberOfSections"):
                sectionsInfo["TOTAL_SECTION"] = str(peRaw.FILE_HEADER.NumberOfSections)
            else:
                sectionsInfo["TOTAL_SECTION"] = "NONE"
        else:
            sectionsInfo["TOTAL_SECTION"] = "NONE"
        sectionsInfo["SECTIONS"] = {}
        try:
            for sct in peRaw.sections:
                try:
                    sctName = str(sct.Name,"utf-8").encode("ascii",errors="ignore").strip().decode("ascii")
                except:
                    sctName = str(sct.Name,"ISO-8859-1").encode("ascii",errors="ignore").strip().decode("ascii")
                sctName = sctName.replace("\u0000","")
                if (sctName is None) or (sctName == "") or (sctName == " "):
                    sctName = ".noname"
                else:
                    pass
                try:
                    popularity = SECTION_MEANS[sctName]
                except:
                    popularity = "NONE"
                if (sct.get_data().decode("latin1","ignore") is not None):
                    try:
                        sctEntropy = CalculateEntropy(sct.get_data().decode("latin1","ignore"))
                    except:
                        sctEntropy = "NOT AVAILABLE TO CALCULATE"
                else:
                    sctEntropy = "NONE"
                isExecutable = CheckIsExecutable(sct)
                try:
                    sctHash = {
                        "MD5":sct.get_hash_md5(),
                        "SHA1":sct.get_hash_sha1(),
                        "SHA256":sct.get_hash_sha256(),
                        "SHA512":sct.get_hash_sha512()
                    }
                except:
                    sctHash = {}
                sctVirtualAddress = sct.VirtualAddress
                sctVirtualSize = sct.Misc_VirtualSize
                sctSizeRawData = sct.SizeOfRawData
                sctNumberRelocations = sct.NumberOfRelocations
                sctCharacteristics = sct.Characteristics
                try:
                    try:
                        sctSample = str(sct.get_data().decode("utf-8","ignore"))[:10]+" ...."
                    except:
                        sctSample = str(sct.get_data().decode("latin1","ignore"))[:10]+" ...."
                except:
                    sctSample = "NONE"
                sectionsInfo["SECTIONS"][sctName] = {
                    "POPULARITY_MEAN":popularity,
                    "ENTROPY":sctEntropy,
                    "EXECUTABLE":isExecutable,
                    "HASH":sctHash,
                    "VIRTUAL_ADDRESS":sctVirtualAddress,
                    "VIRTUAL_ADDRESS_HEX":hex(sctVirtualAddress),
                    "VIRTUAL_SIZE":sctVirtualSize,
                    "VIRTUAL_SIZE_HEX":hex(sctVirtualSize),
                    "SIZE_OF_RAW_DATA":sctSizeRawData,
                    "SIZE_OF_RAW_DATA_HEX":hex(sctVirtualSize),
                    "CHARACTERISTICS":sctCharacteristics,
                    "NUMBER_OF_RELOCATIONS":sctNumberRelocations,
                    "SECTION_SAMPLE":sctSample
                }
        except Exception as err:
            ReturnInitialError(err)
        results = sectionsInfo if (len(sectionsInfo["SECTIONS"]) > 0) else None
        return results
    except Exception as err:
        ReturnInitialError(err)
        return None