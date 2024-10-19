from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from typing import Union,Type

def GetThreatLocalStorage(peRaw:Type[I_Class])->Union[dict,None]:
    tlsRetries = {}
    dirPoint = None
    if hasattr(peRaw,"OPTIONAL_HEADER"):
        if hasattr(peRaw.OPTIONAL_HEADER,"DATA_DIRECTORY"):
            for idx in peRaw.OPTIONAL_HEADER.DATA_DIRECTORY:
                if str(idx.name).rstrip() == "IMAGE_DIRECTORY_ENTRY_TLS":
                    dirPoint = idx
                    break
                else:
                    pass
        else:
            ReturnInitialInfo("NO DATA DIRECTORY")
            return None
    else:
        ReturnInitialInfo("NO OPTIONAL HEADER")
        return None
    if dirPoint is not None:
        try:
            if str(dirPoint.name).rstrip() == "IMAGE_DIRECTORY_ENTRY_TLS":
                try:
                    tlsDirectories = peRaw.parse_directory_tls(dirPoint.VirtualAddress,dirPoint.Size)
                    if hasattr(tlsDirectories,"struct"):
                        tlsRetries.update(
                            {
                                "START_ADDRESS_OF_RAW_DATA":tlsDirectories.struct.StartAddressOfRawData,
                                "START_ADDRESS_OF_RAW_DATA_HEX":hex(tlsDirectories.struct.StartAddressOfRawData),
                                "END_ADDRESS_OF_RAW_DATA":tlsDirectories.struct.EndAddressOfRawData,
                                "END_ADDRESS_OF_RAW_DATA_HEX":hex(tlsDirectories.struct.EndAddressOfRawData),
                                "ADDRESS_OF_INDEX":tlsDirectories.struct.AddressOfIndex,
                                "ADDRESS_OF_CALLBACKS":tlsDirectories.struct.AddressOfCallBacks,
                                "SIZE_OF_ZEROFILL":tlsDirectories.struct.SizeOfZeroFill,
                                "CHARACTERISTICS":tlsDirectories.struct.Characteristics
                            }
                        )
                    else:
                        pass
                except Exception as err:
                    ReturnInitialError(err)
                results = tlsRetries if len(tlsRetries) > 0 else None
                return results
            else:
                ReturnInitialInfo("NO IMAGE DIRECTORY ENTRY TLS")
                return None
        except Exception as err:
            ReturnInitialError(err)
            return None
    else:
        ReturnInitialInfo("NO RELATED DIRECTORY POINT")
        return None
