from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from typing import Union,Type

def GetEntryPoint(peRaw:Type[I_Class])->Union[dict,None]:
    retries = {}
    position = 0
    if hasattr(peRaw,"OPTIONAL_HEADER"):
        if hasattr(peRaw.OPTIONAL_HEADER,"AddressOfEntryPoint"):
            ep = peRaw.OPTIONAL_HEADER.AddressOfEntryPoint
            try:
                for sct in peRaw.sections:
                    if (ep >= sct.VirtualAddress) and (ep < (sct.VirtualAddress+sct.Misc_VirtualSize)):
                        try:
                            name = sct.Name.decode("latin1","ignore").replace("\x00","")
                        except:
                            name = sct.Name.decode("latin1","ignore").replace("\x00","")
                        retries.update(
                            {
                                "EP_POINT":ep,
                                "EP_POINT_HEX":hex(ep),
                                "NAME":name,
                                "POSITION_ID":position
                            }
                        )
                        return retries
                    else:
                        position += 1
            except Exception as err:
                ReturnInitialError(err)
                return None
        else:
            ReturnInitialInfo("NO ADDRESS OF ENTRY POINT")
            return None
    else:
        ReturnInitialInfo("NO OPTIONAL HEADER")
        return None
