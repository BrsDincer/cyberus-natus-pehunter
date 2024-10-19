from utils.scriptFunctions import ReturnInitialInfo,ReturnInitialError
from utils.scriptConstants import DEFAULT_USERAGENT
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Union,Type
import urllib3,json

def GetThreatFoxQuery(fileName:Type[str])->Union[dict,None]:
    resultLast = {}
    baseURL = "threatfox-api.abuse.ch"
    retriesString = GetStringBehaviour(fileName)
    foundIPS = retriesString["FOUND_IP"]
    foundIPS.append("139.180.203.104") #FOR TEST
    if len(foundIPS) > 0:
        pool = urllib3.HTTPSConnectionPool(baseURL,port=443,maxsize=50,timeout=100,headers={"User-Agent":DEFAULT_USERAGENT})
        for ips in foundIPS:
            try:
                requestData = {
                    "query":"search_ioc",
                    "search_term":str(ips)
                }
                rawData = json.dumps(requestData)
                session = pool.request("POST","/api/v1/",body=rawData)
                if 300 > int(session.status) >= 200:
                    try:
                        responseData = session.data.decode("utf-8","ignore")
                    except:
                        responseData = session.data.decode("latin1","ignore")
                    rawResponse = json.loads(responseData)
                    if str(rawResponse["query_status"]).lower() == "ok":
                        mainData = rawResponse["data"]
                        if len(mainData) > 0:
                            for idx,dtInit in enumerate(mainData):
                                dataID = dtInit.get("id","NONE")
                                ioc = dtInit.get("ioc","NONE")
                                iocType = dtInit.get("ioc_type","NONE")
                                threat = dtInit.get("threat_type","NONE")
                                description = dtInit.get("threat_type_desc","NONE")
                                malware = dtInit.get("malware","NONE")
                                malwarePrintable = dtInit.get("malware_printable","NONE")
                                malwareAlias = dtInit.get("malware_alias","NONE")
                                malwareWhat = dtInit.get("malware_malpedia","NONE")
                                firstSeen = dtInit.get("first_seen","NONE")
                                lastSeen = dtInit.get("last_seen","NONE")
                                reporter = dtInit.get("reporter","NONE")
                                samples = dtInit.get("malware_samples","NONE")
                                sampleDict = {}
                                if len(samples) > 0:
                                    for sIDX,spl in enumerate(samples):
                                        timeStamp = spl.get("time_stamp","NONE")
                                        md5 = spl.get("md5_hash","NONE")
                                        sha256 = spl.get("sha256_hash","NONE")
                                        source = spl.get("malware_bazaar","NONE")
                                        sampleDict[str(sIDX+1)] = {
                                            "MALWARE_SAMPLE_TIMESTAMP":timeStamp,
                                            "MALWARE_SAMPLE_MD5":md5,
                                            "MALWARE_SAMPLE_SHA256":sha256,
                                            "MALWARE_SAMPLE_SOURCE":source
                                            }
                                else:
                                    pass
                                resultLast[f"{ips}_ID_{str(idx+1)}"] = {
                                    "DATA_ID":dataID,
                                    "IOC":ioc,
                                    "IOC_TYPE":iocType,
                                    "THREAT_TYPE":threat,
                                    "DESCRIPTION":str(description),
                                    "MALWARE_TYPE":malware,
                                    "MALWARE_PRINTABLE":malwarePrintable,
                                    "MALWARE_ALIAS":malwareAlias,
                                    "MALWARE_DETAIL":malwareWhat,
                                    "FIRST_SEEN":firstSeen,
                                    "LAST_SEEN":lastSeen,
                                    "REPORTER":reporter,
                                    "MALWARE_SAMPLE_INFO":sampleDict
                                }
                        else:
                            pass
                    else:
                        ReturnInitialInfo(f"NO RESULT FROM THREAT FOX FOR {ips}")
                        pass
                else:
                    ReturnInitialInfo(f"SESSION CONNECTION STATUS IS {session.status} FOR {ips}")
                    pass
            except:
                ReturnInitialError("ERROR FROM API SOURCE SYSTEM - CHECK YOUR CONNECTION")
        results = resultLast if len(resultLast) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO IP FROM STRING BEHAVIOUR")
        return None

