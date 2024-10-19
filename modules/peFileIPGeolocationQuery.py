from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Type,Union
from requests.packages.urllib3.exceptions import InsecureRequestWarning,InsecurePlatformWarning
import requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning);requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

def GetIPGeolocationQuery(fileName:Type[str])->Union[dict,None]:
    resultLast = {}
    apiBase = "http://ip-api.com/json/"
    apiFields = "?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    retriesString = GetStringBehaviour(fileName)
    foundIPs = retriesString["FOUND_IP"]
    #foundIPs.append("101.108.146.126") # FOR TEST
    countData = 0
    if len(foundIPs) > 0:
        for ips in foundIPs:
            try:
                targetBase = apiBase+str(ips)+apiFields
                session = requests.get(targetBase,verify=False,stream=True,allow_redirects=True,timeout=100)
                if 300 > session.status_code >= 200:
                    data = session.json()
                    if data:
                        status = data["status"]
                        if str(status).lower() == "success":
                            countData += 1
                            continent = data.get("continent","NONE")
                            continentCode = data.get("continentCode","NONE")
                            country = data.get("country","NONE")
                            countryCode = data.get("countryCode","NONE")
                            regionName = data.get("regionName","NONE")
                            city = data.get("city","NONE")
                            district = data.get("district","NONE")
                            zipCode = data.get("zip","NONE")
                            latitude = data.get("lat","NONE")
                            longitude = data.get("lon","NONE")
                            timeZone = data.get("timezone","NONE")
                            isp = data.get("isp","NONE")
                            organization = data.get("org","NONE")
                            asCode = data.get("as","NONE")
                            asName = data.get("asname","NONE")
                            reverseName = data.get("reverse","NONE")
                            isMobile = data.get("mobile","NONE")
                            isProxy = data.get("proxy","NONE")
                            isHosting = data.get("hosting","NONE")
                            resultLast[f"{str(ips)}_ID_{str(countData)}"] = {
                                "IP":ips,
                                "CONTINENT":continent,
                                "CONTINENT_CODE":continentCode,
                                "COUNTRY":country,
                                "COUNTRY_CODE":countryCode,
                                "REGION":regionName,
                                "CITY":city,
                                "DISTRICT":district,
                                "ZIP":zipCode,
                                "LATITUDE":latitude,
                                "LONGITUDE":longitude,
                                "TIMEZONE":timeZone,
                                "ISP":isp,
                                "AS_CODE":asCode,
                                "AS_NAME":asName,
                                "ORGANIZATION":organization,
                                "REVERSE_NAME":reverseName,
                                "IS_MOBILE":isMobile,
                                "IS_PROXY":isProxy,
                                "IS_HOSTING":isHosting
                            }
                        else:
                            ReturnInitialInfo(f"FAILED FOR {ips}")
                            pass
                    else:
                        ReturnInitialInfo(f"NO DATA RECORD FOR {ips}")
                        pass
                else:
                    ReturnInitialInfo(f"SESSION CONNECTION STATUS IS {session.status_code} FOR {ips}")
                    pass
            except Exception as err:
                ReturnInitialError(err)
                pass
        results = resultLast if len(resultLast) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO IP FROM STRING BEHAVIOUR")
        return None