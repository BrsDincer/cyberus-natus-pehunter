from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from modules.peFileStringBehaviour import GetStringBehaviour
from typing import Union,Type
import re

def GetLogicalString(fileName:Type[str])->Union[dict,None]:
    retries = {}
    retries["LOGICAL_STRINGS"] = []
    stringRetries = GetStringBehaviour(fileName)
    patterns = re.compile(r"[a-zA-Z0-9]+(?:[ '\"\-_]*[a-zA-Z0-9]+)*")
    dumpResult = stringRetries["RESULT_DUMP"]
    def IsMeaningful(initialWord:Type[str])->Type[bool]:
        if len(initialWord) < 4:
            return False
        if any(c.isdigit() for c in initialWord):
            return False
        if re.search(r'[A-Z][a-z][A-Z]|[a-z][A-Z][a-z]',initialWord):
            return False
        if any(c.isalpha() for c in initialWord):
            lettersSum = sum(c.isalpha() for c in initialWord)
            return lettersSum/len(initialWord)>0.8
        return True
    if len(dumpResult) > 0:
        for itm in dumpResult:
            try:
                if (itm != " ") and (itm != "") and (itm is not None):
                    mtc = patterns.findall(str(itm))
                    filterMtc = [idx for idx in mtc if IsMeaningful(idx)]
                    retries["LOGICAL_STRINGS"].extend(filterMtc)
                else:
                    pass
            except Exception as err:
                ReturnInitialError(err)
        results = retries if len(retries["LOGICAL_STRINGS"]) > 0 else None
        return results
    else:
        ReturnInitialInfo("NO FILE DUMP FROM STRING BEHAVIOUR")
        return None