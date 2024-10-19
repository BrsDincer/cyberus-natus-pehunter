from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from utils.scriptDirectories import DIRECTORIES
from typing import Union,Type
import peutils

def GetPackerSignature(peRaw:Type[I_Class])->Union[str,None]:
    retries = {}
    signs = peutils.SignatureDatabase(DIRECTORIES.SIGNATURERESOURCE)
    matches = signs.match(peRaw,ep_only=True)
    if matches is not None:
        try:
            for cnt,mx in enumerate(matches):
                retries[str(cnt+1)] = mx
        except Exception as err:
            ReturnInitialError(err)
        results = retries if len(retries) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO MATCH FOR PACKERS")
        return None

