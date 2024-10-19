from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialInfo,ReturnInitialError
from typing import Type,Union

def GetExports(peRaw:Type[I_Class])->Union[dict,None]:
    exports = {}
    if hasattr(peRaw,"DIRECTORY_ENTRY_EXPORT"):
        if hasattr(peRaw.DIRECTORY_ENTRY_EXPORT,"symbols"):
            try:
                for exp in peRaw.DIRECTORY_ENTRY_EXPORT.symbols:
                    try:
                        expName = str(exp.name.decode("utf-8","ignore")).rstrip()
                    except:
                        expName = str(exp.name.decode("latin1","ignore")).rstrip()
                    if (expName is None) or (expName == "") or (expName == " "):
                        expName = "NONE"
                    else:
                        pass
                    expRawAddr = exp.address
                    if hasattr(peRaw,"OPTIONAL_HEADER"):
                        if hasattr(peRaw.OPTIONAL_HEADER,"ImageBase"):
                            expBaseAddr = peRaw.OPTIONAL_HEADER.ImageBase+exp.address
                        else:
                            expBaseAddr = "NONE"
                    else:
                        expBaseAddr = "NONE"
                    expAddressOffset = exp.address_offset
                    expOrdinal = exp.ordinal
                    expOrdinalOffset = exp.ordinal_offset
                    exports[expName] = {
                        "ADDRESS_RAW":expRawAddr,
                        "ADDRESS_RAW_HEX":hex(expRawAddr),
                        "ADDRESS_OFFSET":expAddressOffset,
                        "ADDRESS_OFFSET_HEX":hex(expAddressOffset),
                        "OFFSET_MAIN":expBaseAddr,
                        "OFFSET_MAIN_HEX":hex(expBaseAddr),
                        "ORDINAL":expOrdinal,
                        "ORDINAL_OFFSET":expOrdinalOffset
                    }
            except Exception as err:
                ReturnInitialError(err)
            results = exports if len(exports) > 0 else None
            return results
        else:
            ReturnInitialInfo("NO EXPORT INFORMATION")
            return None
    else:
        ReturnInitialInfo("NO ENTRY EXPORT INFORMATION")
        return None