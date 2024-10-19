from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialInfo,CalculateEntropy
from typing import Union,Type
import time,hashlib

def GetGeneralInformation(peRaw:Type[I_Class],fileRaw:Type[bytes])->Union[dict,None]:
    fileInfo = {}
    if hasattr(peRaw,"FILE_HEADER"):
        if hasattr(peRaw.FILE_HEADER,"TimeDateStamp"):
            value = peRaw.FILE_HEADER.TimeDateStamp
            gm = time.gmtime(value)
            timestamp = time.asctime(gm)
        else:
            ReturnInitialInfo("NO TIME DATE STAMP HEADER")
            timestamp = "NONE"
        if hasattr(peRaw.FILE_HEADER,"IMAGE_FILE_DLL"):
            imageDLL = peRaw.FILE_HEADER.IMAGE_FILE_DLL
        else:
            ReturnInitialInfo("NO IMAGE FILE DLL HEADER")
            imageDLL = "NONE"
    else:
        ReturnInitialInfo("NO FILE HEADER")
        timestamp = "NONE"
        imageDLL = "None"
    if hasattr(peRaw,"OPTIONAL_HEADER"):
        if hasattr(peRaw.OPTIONAL_HEADER,"ImageBase"):
            imageBASE = peRaw.OPTIONAL_HEADER.ImageBase
        else:
            imageBASE = "NONE"
        if hasattr(peRaw.OPTIONAL_HEADER,"AddressOfEntryPoint"):
            entryPoint = peRaw.OPTIONAL_HEADER.AddressOfEntryPoint
        else:
            entryPoint = "NONE"
        if hasattr(peRaw.OPTIONAL_HEADER,"CheckSum"):
            actualChecksum = peRaw.OPTIONAL_HEADER.CheckSum
        else:
            actualChecksum = "NONE"
    else:
        imageBASE = "NONE"
        entryPoint = "NONE"
    try:
        impHash = peRaw.get_imphash()
    except:
        impHash = "NONE"
    try:
        peMD5 = hashlib.md5(fileRaw).hexdigest()
    except:
        peMD5 = "NONE"
    try:
        peSHA1 = hashlib.sha1(fileRaw).hexdigest()
    except:
        peSHA1 = "NONE"
    try:
        peSHA256 = hashlib.sha256(fileRaw).hexdigest()
    except:
        peSHA256 = "NONE"
    try:
        peSHA512 = hashlib.sha512(fileRaw).hexdigest()
    except:
        peSHA512 = "NONE"
    try:
        dataPE = peRaw.get_data().decode("latin","ignore")
        entropy = round(CalculateEntropy(dataPE),5)
    except:
        entropy = "NONE"
    try:
        checksum = peRaw.generate_checksum()
    except:
        checksum = "NONE"
    fileInfo.update(
        {
            "TIMESTAMP":timestamp,
            "DLL":imageDLL,
            "IMAGE_BASE":imageBASE,
            "IMAGE_BASE_HEX":hex(imageBASE),
            "ENTRY_POINT":entryPoint,
            "ENTRY_POINT_HEX":hex(entryPoint),
            "IMP_HASH":impHash,
            "MD5_HASH":peMD5,
            "SHA1_HASH":peSHA1,
            "SHA256_HASH":peSHA256,
            "SHA512_HASH":peSHA512,
            "FILE_ENTROPY":entropy,
            "FILE_CHECKSUM":checksum,
            "FILE_CHECKSUM_HEX":hex(checksum),
            "ACTUAL_CHECKSUM":actualChecksum,
            "ACTUAL_CHECKSUM_HEX":hex(actualChecksum)
        }
    )
    return fileInfo
    

    
    
