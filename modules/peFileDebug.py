from utils.scriptFunctions import I_Class
from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from utils.scriptConstants import DEBUG_TYPES
from typing import Type,Union

def GetDebugTypes(peRaw:Type[I_Class])->Union[dict,None]:
    debugs = {}
    if hasattr(peRaw,"OPTIONAL_HEADER"):
        if hasattr(peRaw.OPTIONAL_HEADER,"DATA_DIRECTORY"):
            for drt in peRaw.OPTIONAL_HEADER.DATA_DIRECTORY:
                if str(drt.name).rstrip() == "IMAGE_DIRECTORY_ENTRY_DEBUG":
                    break
                else:
                    pass
            if str(drt.name).rstrip() == "IMAGE_DIRECTORY_ENTRY_DEBUG":
                debugDirectories = peRaw.parse_debug_directory(drt.VirtualAddress,drt.Size)
                try:
                    for debug in debugDirectories:
                        if hasattr(debug,"struct"):
                            if hasattr(debug.struct,"Type"):
                                if debug.struct.Type == DEBUG_TYPES["IMAGE_DEBUG_TYPE_CODEVIEW"]:
                                    debugs.update(
                                        {
                                            "TIME_STAMP":debug.struct.TimeDateStamp,
                                            "POINTER_TO_RAW_DATA":debug.struct.PointerToRawData,
                                            "POINTER_TO_RAW_DATA_HEX":hex(debug.struct.PointerToRawData),
                                            "ADDRESS_OF_RAW_DATA":debug.struct.AddressOfRawData,
                                            "ADDRESS_TO_RAW_DATA_HEX":hex(debug.struct.AddressOfRawData),
                                            "SIZE_OF_DATA":debug.struct.SizeOfData
                                        }
                                    )
                                    return debugs
                            else:
                                pass
                        else:
                            pass
                except Exception as err:
                    ReturnInitialError(err)
                results = debugs if len(debugs) > 0 else None
                return results
            else:
                ReturnInitialInfo("NOT ENTRY DEBUG")
                return None
        else:
            ReturnInitialInfo("NO DATA DIRECTORY")
            return None
    else:
        ReturnInitialInfo("NO OPTIONAL HEADER")
        return None
