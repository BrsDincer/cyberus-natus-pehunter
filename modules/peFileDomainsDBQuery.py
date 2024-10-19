from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo,DeleteHTTPTag
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Union,Type
from requests.packages.urllib3.exceptions import InsecureRequestWarning,InsecurePlatformWarning
import requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning);requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

def GetDomainsDBQuery(fileName:Type[str],countLimit:Type[int]=10)->Union[dict,None]:
    resultLast = {}
    apiBase = "https://api.domainsdb.info/v1/domains/search?domain="
    retriesString = GetStringBehaviour(fileName)
    foundServices = retriesString["FOUND_SERVICE"]
    #foundServices.append("proxy.amazonscouts.com") # FOR TEST
    #foundServices.append("sourceforge.net") # FOR TEST
    if len(foundServices):
        cleanServices = [DeleteHTTPTag(srv) for srv in foundServices]
        cleanServices = list(set([srvInit.split("/")[0] for srvInit in cleanServices]))
        try:
            for srvInit in cleanServices:
                queryBase = apiBase+str(srvInit)+f"&limit={str(countLimit)}"
                session = requests.get(queryBase,verify=False,stream=True,allow_redirects=True,timeout=100)
                if 300 > session.status_code >= 200:
                    data = session.json()
                    if data:
                        returnDomains = data["domains"]
                        if returnDomains:
                            try:
                                for cnt,init in enumerate(returnDomains):
                                    mainDomain = init.get("domain","NONE")
                                    countryDomain = init.get("country","NONE")
                                    isDead = init.get("isDead","NONE")
                                    aRecord = init.get("A","NONE")
                                    nsRecord = init.get("NS","NONE")
                                    cnameRecord = init.get("CNAME","NONE")
                                    txtRecord = init.get("TXT","NONE")
                                    mxRecord = init.get("MX","NONE")
                                    if (mxRecord != "NONE") and (mxRecord is not None) and (mxRecord != "null"):
                                        mainMX = {}
                                        if isinstance(mxRecord,dict):
                                            for key,val in mxRecord.items():
                                                mainMX[str(key)] = str(val)
                                        elif isinstance(mxRecord,list):
                                            for cnt,mxInit in enumerate(mxRecord):
                                                for kMX,vMX in mxInit.items():
                                                    mainMX[f"{str(kMX).upper()}_{str(cnt+1)}"] = str(vMX)
                                        else:
                                            mainMX = mxRecord
                                    else:
                                        pass
                                    resultLast[f"{srvInit}_{str(cnt+1)}"] = {
                                        "DOMAIN":mainDomain,
                                        "COUNTRY":countryDomain,
                                        "IS_DEAD":isDead,
                                        "A":aRecord,
                                        "NS":nsRecord,
                                        "CNAME":cnameRecord,
                                        "TXT":txtRecord,
                                        "MX":mainMX
                                    }
                            except:
                                pass
                        else:
                            ReturnInitialInfo(f"NO DOMAIN RECORD FOR {srvInit}")
                            pass
                    else:
                        ReturnInitialInfo(f"NO DATA RECORD FOR {srvInit}")
                        pass
                else:
                    ReturnInitialInfo(f"SESSION CONNECTION STATUS IS {session.status_code} FOR {srvInit}")
                    pass
        except Exception as err:
            ReturnInitialError(err)
        results = resultLast if len(resultLast) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO URL FROM STRING BEHAVIOUR")
        return None