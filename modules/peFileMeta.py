from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialInfo,ReturnInitialError
from typing import Type,Union

def GetFileMetadata(peRaw:Type[I_Class])->Union[dict,None]:
    retries = {}
    if hasattr(peRaw,"VS_VERSIONINFO"):
        if hasattr(peRaw,"FileInfo"):
            try:
                for infoRaw in peRaw.FileInfo:
                    for entry in infoRaw:
                        if hasattr(entry,"StringTable"):
                            for st in entry.StringTable:
                                for key,value in list(st.entries.items()):
                                    retries.update({key.decode("utf-8").rstrip():value.decode("utf-8").rstrip()})
                        else:
                            pass
            except Exception as err:
                ReturnInitialError(err)
            results = retries if len(retries) > 0 else None
            return results
        else:
            ReturnInitialInfo("NO FILE INFORMATION")
            return None
    else:
        ReturnInitialInfo("NO FILE VERSION INFORMATION")
        return None