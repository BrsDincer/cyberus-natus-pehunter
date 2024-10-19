from utils.scriptConstants import VM_SIGNS
from utils.scriptFunctions import ReturnInitialError
from typing import Type,Union

def GetAntiVM(fileRaw:Type[bytes])->Union[dict,None]:
    retries = {}
    try:
        for key,value in VM_SIGNS.items():
            isPOS = fileRaw.find(value)
            if isPOS > -1:
                retries.update(
                    {
                        "TRICK":key,
                        "OFFSET":isPOS,
                        "OFFSET_HEX":hex(isPOS)
                    }
                )
            else:
                pass
    except Exception as err:
        ReturnInitialError(err)
    results = retries if len(retries) > 0 else None
    return results