from utils.scriptUtilization import I_Class
from utils.scriptDirectories import DIRECTORIES
from utils.scriptFunctions import ReturnInitialInfo,ReturnInitialError,ConvertPathFile,ReplaceFormats,CalculateEntropy
from typing import Type,Union
import binascii,uuid,hashlib,os

def GetOverlay(peRaw:Type[I_Class],isSaved:Type[bool]=True)->Union[dict,None]:
    retries = {}
    try:
        peOverlayData = peRaw.get_overlay()
        if (peOverlayData is not None) and (peOverlayData != b" "):
            ReturnInitialInfo("OVERLAY IS PRESENT")
            try:
                if bool(isSaved) == True:
                    newPathName = os.path.join(DIRECTORIES.RESULTPATH,f"OVERLAY_{ReplaceFormats(uuid.uuid4())}.bin")
                    with open(newPathName,"wb") as wps:
                        wps.write(peOverlayData)
                    ReturnInitialInfo(f"OVERLAY HAS BEEN SAVED AS BIN FILE TO {newPathName}")
                try:
                    decodedData = binascii.hexlify(peOverlayData).decode("latin1","ignore")
                except:
                    decodedData = binascii.hexlify(peOverlayData).decode("latin1","ignore")
                try:
                    entropy = round(CalculateEntropy(decodedData),5)
                except:
                    entropy = "NONE"
                md5 = hashlib.md5(peOverlayData).hexdigest()
                sha1 = hashlib.sha1(peOverlayData).hexdigest()
                sha256 = hashlib.sha256(peOverlayData).hexdigest()
                sha512 = hashlib.sha512(peOverlayData).hexdigest()
                retries.update(
                    {
                        "DATA_SAMPLE":peOverlayData[:20],
                        "ENTROPY":entropy,
                        "MD5":md5,
                        "SHA1":sha1,
                        "SHA256":sha256,
                        "SHA512":sha512
                    }
                )
            except Exception as err:
                ReturnInitialError(err)
            results = retries if len(retries) > 0 else None
            return results
        else:
            ReturnInitialInfo("THERE IS NO OVERLAY")
            return None
    except Exception as err:
        ReturnInitialError(err)
        return None
