from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo,CreateDirectory
from utils.scriptDirectories import DIRECTORIES
from modules.peFileDigitalSideIPQuery import GetDigitalSideIP
from modules.peFileDigitalSideURLQuery import GetDigitalSideURL
from typing import Union,Type
from apiosintDS import apiosintDS

def GetDigitalSideAPI(fileName:Type[str])->Union[dict,None]:
    extList = []
    resultLast = {}
    countData = 0
    retriesDigitalSiedIPs = GetDigitalSideIP(fileName)
    retriesDigitalSideURLs = GetDigitalSideURL(fileName)
    CreateDirectory(DIRECTORIES.CACHEPATH)
    if retriesDigitalSiedIPs is not None:
        targetIPs = []
        for _,value in retriesDigitalSiedIPs.items():
            targetIPs.append(value["POTENTIAL_MALICIOUS_IP"])
    else:
        targetIPs = []
    if retriesDigitalSideURLs is not None:
        targetURLs = []
        for _,value in retriesDigitalSideURLs.items():
            targetURLs.append(value["PATTERN_CLEAR"])
    else:
        targetURLs = []
    if len(targetIPs) > 0:
        extList.extend(targetIPs)
    else:
        pass
    if len(targetURLs) > 0:
        extList.extend(targetURLs)
    else:
        pass
    #extList.append("101.108.146.126")#FOR TEST
    if len(extList) > 0:
        dataCheck = apiosintDS.request(
            entities=extList,
            stix=True,
            cache=True,
            cachedirectory=DIRECTORIES.CACHEPATH,
            verbose=True,
            clearcache=True
        )
        if dataCheck:
            keyList = list(dataCheck.keys())
            try:
                for keyInit in keyList:
                    if (keyInit != "apiosintDSversion") and (keyInit != "generalstatistics"):
                        mainData =dataCheck[keyInit]["items"]
                        if len(mainData) > 0:
                            for initData in mainData:
                                responseOK = initData["response"]
                                if responseOK:
                                    countData += 1
                                    itemData = initData["item"]
                                    relatedURLs = initData["related_urls"]
                                    relatedURLDict = {}
                                    if len(relatedURLs) > 0:
                                        for cnt,itemRelated in enumerate(relatedURLs):
                                            try:
                                                try:
                                                    urlRelated = itemRelated["url"]
                                                except:
                                                    urlRelated = "NONE"
                                                try:
                                                    md5Related = itemRelated["hashes"].get("md5","NONE")
                                                except:
                                                    md5Related = "NONE"
                                                try:
                                                    sha1Related = itemRelated["hashes"].get("sha1","NONE")
                                                except:
                                                    sha1Related = "NONE"
                                                try:
                                                    sha256Related = itemRelated["hashes"].get("sha256","NONE")
                                                except:
                                                    sha256Related = "NONE"
                                                try:
                                                    onlineRelatedMISP = itemRelated["online_reports"].get("MISP_EVENT","NONE")
                                                except:
                                                    onlineRelatedMISP = "NONE"
                                                try:
                                                    onlineRelatedSTIX = itemRelated["online_reports"].get("STIX","NONE")
                                                except:
                                                    onlineRelatedSTIX = "NONE"
                                                try:
                                                    onlineRelatedVirusTotal = itemRelated["online_reports"]["STIXDETAILS"]["virus_total"].get("vt_report","NONE")
                                                    if onlineRelatedVirusTotal:
                                                        onlineRelatedVirusTotalReport = itemRelated["online_reports"]["STIXDETAILS"]["virus_total"].get("vt_report","NONE")
                                                    else:
                                                        onlineRelatedVirusTotalReport = "NONE"
                                                except:
                                                    onlineRelatedVirusTotalReport = "NONE"
                                                try:
                                                    relatedFileName = itemRelated["online_reports"]["STIXDETAILS"].get("filename","NONE")
                                                except:
                                                    relatedFileName = "NONE"
                                                try:
                                                    relatedFileSize = itemRelated["online_reports"]["STIXDETAILS"].get("filesize","NONE")
                                                except:
                                                    relatedFileSize = "NONE"
                                                try:
                                                    relatedFileMIME = itemRelated["online_reports"]["STIXDETAILS"].get("mime_type","NONE")
                                                except:
                                                    relatedFileMIME = "NONE"
                                                relatedURLDict[str(cnt+1)] = {
                                                    "URL":urlRelated,
                                                    "MD5":md5Related,
                                                    "SHA1":sha1Related,
                                                    "SHA256":sha256Related,
                                                    "MISP_REPORT_SOURCE":onlineRelatedMISP,
                                                    "STIX_REPORT_SOURCE":onlineRelatedSTIX,
                                                    "VIRUS_TOTAL_SOURCE":onlineRelatedVirusTotalReport,
                                                    "TARGET_FILE_NAME":relatedFileName,
                                                    "TARGET_FILE_SIZE":relatedFileSize,
                                                    "TARGET_FILE_MIME":relatedFileMIME
                                                        }
                                            except Exception as err:
                                                pass
                                    else:
                                        pass
                                    resultLast[f"{itemData}_ID_{countData}"] = relatedURLDict
                                else:
                                    pass
                        else:
                            pass
                    else:
                        pass
            except Exception as err:
                ReturnInitialError(err)
            results = resultLast if len(resultLast) > 0 else None
            return results
        else:
            ReturnInitialInfo("NO DIGITAL SIDE DATA FOUND")
            return None
    else:
        ReturnInitialInfo("RECORDED IP OR URL NOT FOUND")
        return None
