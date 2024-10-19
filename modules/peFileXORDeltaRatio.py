from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo,DetectRepeatingPattern
from typing import Union,Type

def GetXORDeltaRatio(peRaw:Type[I_Class])->Union[dict,None]:
    deltas = []
    retries = {}
    for sct in peRaw.sections:
        try:
            dataRaw = sct.get_data()
            if len(dataRaw) < 2:
                try:
                    sctName = sct.Name.decode("utf-8","ignore").strip().replace("\00","")
                except:
                    sctName = sct.Name.decode("latin1","ignore").strip().replace("\00","")
                ReturnInitialInfo(f"NOT ENOUGH DATA IN {sctName} FOR XOR DELTA ANALYSIS")
                continue
            for idx in range(1,len(dataRaw)):
                point = dataRaw[idx]^dataRaw[idx-1]
                deltas.append(point)
            if len(deltas) > 0:
                try:
                    sctName = sct.Name.decode("utf-8","ignore").strip().replace("\00","")
                except:
                    sctName = sct.Name.decode("latin1","ignore").strip().replace("\00","")
                isRepeating,ratio = DetectRepeatingPattern(deltas)
                if isRepeating:
                    retries[sctName] = {
                        "STATUS":"POTENTIAL_XOR_DELTA",
                        "XOR_DELTA_RATIO":ratio
                    }
                else:
                    retries[sctName] = {
                        "STATUS":"LOW_RATIO_XOR_DELTA",
                        "XOR_DELTA_RATIO":ratio
                    }
            else:
                pass
        except Exception as err:
            ReturnInitialError(err)
    results = retries if len(retries) > 0 else None
    return results