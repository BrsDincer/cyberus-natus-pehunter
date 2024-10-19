from utils.scriptFunctions import ReturnInitialInfo
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Union,Type
import re

def GetPII(fileName:Type[str])->Union[dict,None]:
    retries = {}
    retries["PII_RESULT"] = {
         "POTENTIAL_EMAILS":[],
         "POTENTIAL_PHONE":[],
         "POTENTIAL_SSNS":[],
         "POTENTIAL_CREDITCARD":[],
         "POTENTIAL_POSTALCODE":[],
         "POTENTIAL_DRIVERLICENSE":[]
    }
    stringRetries = GetStringBehaviour(fileName)
    dumpResult = stringRetries["RESULT_DUMP"]
    """
    dumpResult.append("5365555555") #FOR TEST
    dumpResult.append("+1 (555) 123-4567") #FOR TEST
    dumpResult.append("something@something.com") #FOR TEST
    dumpResult.append("john.doe@com") #FOR TEST
    dumpResult.append("5500-0000-0000-0004") #FOR TEST
    dumpResult.append("12345-6789") #FOR TEST
    dumpResult.append("A123456") #FOR TEST
    dumpResult.append("222-77-1234") #FOR TEST
    """
    emailPattern = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
    phonePattern = re.compile(r"\b(?:\+?(\d{1,3}))?[-.\s]?\(?\d{1,4}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b")
    ssnPattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    creditCardPattern = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
    postalCodePattern = re.compile(r"\b\d{5}(?:[-\s]\d{4})?\b")
    driverLicensePattern = re.compile(r"[A-Z0-9]{6,9}")
    if len(dumpResult) > 0:
        for itm in dumpResult:
            try:
                if len(itm) > 4:
                    if emailPattern.search(itm):
                        if itm not in retries["PII_RESULT"]["POTENTIAL_EMAILS"]:
                            retries["PII_RESULT"]["POTENTIAL_EMAILS"].append(itm)
                    if phonePattern.search(itm):
                        if 7 <= len(itm) <= 15:
                            if itm not in retries["PII_RESULT"]["POTENTIAL_PHONE"]:
                                retries["PII_RESULT"]["POTENTIAL_PHONE"].append(itm)
                        else:
                            pass
                    if ssnPattern.search(itm):
                        if itm not in retries["PII_RESULT"]["POTENTIAL_SSNS"]:
                            retries["PII_RESULT"]["POTENTIAL_SSNS"].append(itm)
                    if creditCardPattern.search(itm):
                        if itm not in retries["PII_RESULT"]["POTENTIAL_CREDITCARD"]:
                            retries["PII_RESULT"]["POTENTIAL_CREDITCARD"].append(itm)
                    if postalCodePattern.search(itm):
                        if itm not in retries["PII_RESULT"]["POTENTIAL_POSTALCODE"]:
                            retries["PII_RESULT"]["POTENTIAL_POSTALCODE"].append(itm)
                    if driverLicensePattern.search(itm):
                        if itm not in retries["PII_RESULT"]["POTENTIAL_DRIVERLICENSE"]:
                            retries["PII_RESULT"]["POTENTIAL_DRIVERLICENSE"].append(itm)             
                else:
                    pass
            except:
                pass
        return retries
    else:
        ReturnInitialInfo("NO FILE DUMP FROM STRING BEHAVIOUR")
        return None