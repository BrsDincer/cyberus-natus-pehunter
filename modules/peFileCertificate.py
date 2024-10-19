from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from typing import Union,Type
from asn1crypto import cms

def GetCertificate(peRaw:Type[I_Class])->Union[dict,None]:
    retries = {}
    if hasattr(peRaw,"OPTIONAL_HEADER"):
        if hasattr(peRaw.OPTIONAL_HEADER,"DATA_DIRECTORY"):
            for init in peRaw.OPTIONAL_HEADER.DATA_DIRECTORY:
                if str(init.name).rstrip() == "IMAGE_DIRECTORY_ENTRY_SECURITY":
                    break
                else:
                    pass
            try:
                if str(init.name).rstrip() == "IMAGE_DIRECTORY_ENTRY_SECURITY":
                    certAddress = init.VirtualAddress
                    certSize = init.Size
                    if (certAddress != 0) and (certSize) != 0:
                        signature = peRaw.write()[certAddress+8:]
                        transSignature = cms.ContentInfo.load(bytes(signature))
                        if len(transSignature["content"]["certificates"]) > 0:
                            try:
                                for crtIdx,certInit in enumerate(transSignature["content"]["certificates"]):
                                    if hasattr(certInit,"native"):
                                        info = dict(certInit.native)
                                        if info and len(info) > 0:
                                            tbs = dict(info["tbs_certificate"])
                                            if tbs and (len(tbs) > 0):
                                                try:
                                                    version = tbs["version"]
                                                except:
                                                    version = ""
                                                try:
                                                    serialNumber = tbs["serial_number"]
                                                except:
                                                    serialNumber = ""
                                                try:
                                                    signAlgorithm = dict(tbs["signature"])["algorithm"]
                                                except:
                                                    signAlgorithm = ""
                                                try:
                                                    issuerCountry = dict(tbs["issuer"])["country_name"]
                                                except:
                                                    issuerCountry = ""
                                                try:
                                                    issuerOrganization = dict(tbs["issuer"])["organization_name"]
                                                except:
                                                    issuerOrganization = ""
                                                try:
                                                    issuerCommonName = dict(tbs["issuer"])["common_name"]
                                                except:
                                                    issuerCommonName = ""
                                                try:
                                                    notBefore = str(dict(tbs["validity"])["not_before"])
                                                except:
                                                    notBefore = ""
                                                try:
                                                    notAfter = str(dict(tbs["validity"])["not_after"])
                                                except:
                                                    notAfter = ""
                                                try:
                                                    subCountry = dict(tbs["subject"])["country_name"]
                                                except:
                                                    subCountry = ""
                                                try:
                                                    subState = dict(tbs["subject"])["state_or_province_name"]
                                                except:
                                                    subState = ""
                                                try:
                                                    subLocality = dict(tbs["subject"])["locality_name"]
                                                except:
                                                    subLocality = ""
                                                try:
                                                    subOrganization = dict(tbs["subject"])["organization_name"]
                                                except:
                                                    subOrganization = ""
                                                try:
                                                    subEmail = dict(tbs["subject"])["email_address"]
                                                except:
                                                    subEmail = ""
                                                try:
                                                    details = {
                                                            "VERSION":version,
                                                            "SERIAL_NUMBER":serialNumber,
                                                            "SIGN_ALGORITHM":signAlgorithm,
                                                            "ISSUER_COUNTRY":issuerCountry,
                                                            "ISSUER_ORGANIZATION":issuerOrganization,
                                                            "COMMON_NAME":issuerCommonName,
                                                            "VALID_FROM":notBefore,
                                                            "VALID_TO":notAfter,
                                                            "COUNTRY":subCountry,
                                                            "STATE_PROVINCE":subState,
                                                            "LOCALITY":subLocality,
                                                            "ORGANIZATION":subOrganization,
                                                            "EMAIL":subEmail
                                                            }
                                                except:
                                                    details = None
                                                if details is not None:
                                                    retries[crtIdx] = {
                                                            "VIRTUAL_ADDRESS":certAddress,
                                                            "VIRTUAL_ADDRESS_HEX":hex(certAddress),
                                                            "BLOCK_SIZE":certSize,
                                                            "DETAILS":details
                                                            }
                                                else:
                                                    retries[crtIdx] = {
                                                            "VIRTUAL_ADDRESS":certAddress,
                                                            "VIRTUAL_ADDRESS_HEX":hex(certAddress),
                                                            "BLOCK_SIZE":certSize,
                                                            "DETAILS":"NONE"
                                                            }
                                            else:
                                                pass
                                        else:
                                            pass
                                    else:
                                        pass
                            except Exception as err:
                                ReturnInitialError(err)
                                return None
                        else:
                            ReturnInitialInfo("NO CERTIFICATE")
                            return None
                else:
                    ReturnInitialInfo("NO DIRECTORY ENTRY SECURITY")
                    return None
            except Exception as err:
                ReturnInitialError(err)
            results = retries if len(retries) > 0 else None
            return results
        else:
            ReturnInitialInfo("NO DATA DIRECTORY")
            return None
    else:
        ReturnInitialInfo("NO OPTIONAL HEADER")
        return None