from utils.scriptUtilization import I_Function,I_Class
from utils.scriptConstants import STRING_REPLACE_FORMATS,DEFAULT_USERAGENT
from utils.scriptDirectories import DIRECTORIES
from typing import Type,Union
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning,InsecurePlatformWarning
import os,shutil,functools,string,magic,sys,json,math,re,binascii,requests,pprint
requests.packages.urllib3.disable_warnings(InsecureRequestWarning);requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

CreateDirectory:Type[I_Function] = lambda path:os.makedirs(str(path),exist_ok=True)
DeleteDirectory:Type[I_Function] = lambda path:shutil.rmtree(str(path)) if (len(os.listdir(path)) > 0) and (os.path.exists(str(path))) else None
ReplaceFormats:Type[I_Function] = lambda name:functools.reduce(lambda val,key:val.replace(*key),STRING_REPLACE_FORMATS.items(),str(name))
DeleteHTTPTag:Type[I_Function] = lambda url:url.replace("http://","").replace("https://","")
ReturnOS:Type[I_Function] = lambda:str(os.name)
GetTimeNow:Type[I_Function] = lambda:datetime.now()
GetIsFile:Type[I_Function] = lambda path:True if os.path.isfile(str(path)) else False
GetFileMagic:Type[I_Function] = lambda raw:magic.from_buffer(raw) if "magic" in sys.modules.keys() else None
IsMagicPE:Type[I_Function] = lambda data:re.findall(r"4d5a90",str(binascii.b2a_hex(data))) if data is not None else False
ConvertCharacters:Type[I_Function] = lambda character:character if (character in string.ascii_letters) or (character in string.digits) or (character in string.punctuation) or (character in string.whitespace) else r'\x%02x'%ord(character)
MakePrintable:Type[I_Function] = lambda bulks:"".join([ConvertCharacters(piece) for piece in bulks]) if (isinstance(bulks,list)) or (isinstance(bulks,tuple)) else None
ReturnInitialInfo:Type[I_Function] = lambda message:print(f"[INITIAL MESSAGE] >> {str(message)} << [INFO]")
ReturnInitialError:Type[I_Function] = lambda message:print(f"[INITIAL MESSAGE] >> {str(message)} << [ERROR]")
ConvertPathFile:Type[I_Function] = lambda name,folder:os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),folder,name)
FindServiceName:Type[I_Function] = lambda input:re.findall(r'((smb|srm|ssh|ftps?|file|https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)',input,re.MULTILINE)
FindIPEntry:Type[I_Function] = lambda input:re.findall(r'[0-9]+(?:\.[0-9]+){3}',str(input))
FindFileEntry:Type[I_Function] = lambda input:re.findall("(.+(\.([a-z]{2,3}$)|\/.+\/|\\\.+\\\))+",input,re.IGNORECASE|re.MULTILINE)
#FindFileEntry:Type[I_Function] = lambda input: re.findall(r"(.+\.(?:[a-z]{2,3})$|/.+/|\\.+\\)+", input, re.IGNORECASE | re.MULTILINE)


def LoadJSONConfiguration()->Type[dict]:
    with open(DIRECTORIES.MATCHRESOURCE) as jsonconf:
        dataJSON = json.load(jsonconf)
    return dataJSON

def CalculateEntropy(rawData:Union[bytes,str])->Type[float]:
    entropy = 0
    for idx in range(256):
        score = rawData.count(chr(idx))/len(rawData)
        if score > 0:
            entropy += -score*math.log2(score)
        else:
            pass
    return entropy

def CheckIsExecutable(rawData:Type[I_Class])->Union[bool,None]:
    if hasattr(rawData,"Characteristics"):
        character = getattr(rawData,"Characteristics")
        if (character & 0x00000020 > 0) or (character & 0x20000000 > 0):
            return True
        else:
            return False
    else:
        return None
    
def CheckValidIPInput(address:Type[str])->Type[bool]:
    try:
        hostInitial = address.split(".")
        validation = [int(init) for init in hostInitial]
        validation = [bt for bt in validation if bt >= 0 and bt <= 255]
        return len(hostInitial) == 4 and len(validation) == 4
    except:
        return False
    
def GetApproveCharacter()->Type[str]:
    characterSample = ["\0"]*256
    for idx in range(32,127):
        characterSample[idx] = chr(idx)
    characterSample[ord("\t")]="\t"
    return "".join(characterSample)

def TranslateApproveCharacter(fileName:Type[str],threshold:Type[int]=4)->Type[list]:
    results = []
    for sdx in open(fileName,errors="ignore").read().translate(GetApproveCharacter()).split("\0"):
        if len(sdx) >= threshold:
            results.append(sdx)
        else:
            pass
    return results

def DetectRepeatingPattern(raw:Union[bytes,str],threshold:Type[float]=0.7)->Type[tuple]:
    if len(raw) != 0:
        count = sum(1 for idx in range(1,len(raw)) if raw[idx] == raw[idx-1])
        ratio = count/len(raw)
        return (ratio >= threshold,round(ratio,4))
    else:
        return (False,round(ratio,4))

def GetOnlineSigmaSource(urlTarget:Type[str])->Union[bool,None]:
    CreateDirectory(DIRECTORIES.SIGMAPATH)
    baseSigma = "https://raw.githubusercontent.com/SigmaHQ/sigma/"
    section = re.search(r"blob/(.*)",urlTarget).group(1)
    saveBase = section.split("/")[-1].split(".")
    saveName = saveBase[0]
    saveExt = saveBase[-1]
    savePath = os.path.join(DIRECTORIES.SIGMAPATH,f"{saveName}.{saveExt}")
    target = baseSigma+section
    session = requests.get(target,verify=False,timeout=100,allow_redirects=True,stream=True,headers={"User-Agent":DEFAULT_USERAGENT})
    if 300 > session.status_code >= 200:
        content = session.text
        with open(savePath,"w") as wops:
            wops.write(content)
        ReturnInitialInfo(f"SIGMA RULE HAS BEEN SAVED TO {savePath}")
        return True
    else:
        return None
    
def UpdateResources(isUpdate:Type[bool]=False)->Union[bool,None]:
    if isUpdate:
        url = "https://lolbas-project.github.io/api/lolbas.json"
        session = requests.get(url,verify=False,timeout=100,allow_redirects=True,stream=True,headers={"User-Agent":DEFAULT_USERAGENT})
        if 300 > session.status_code >= 200:
            data = session.json()
            with open(DIRECTORIES.BINARYCHECKSOURCE,"w") as wops:
                json.dump(data,wops,indent=4)
            ReturnInitialInfo(f"LOLBAS BINARY DATA HAS BEEN SAVED TO {DIRECTORIES.BINARYCHECKSOURCE}")
        else:
            ReturnInitialInfo("LOLBAS BINARY DATA IS NOT AVAILABLE FOR NOW")
    if isUpdate:
        url = "https://www.loldrivers.io/api/drivers.json"
        session = requests.get(url,verify=False,timeout=100,allow_redirects=True,stream=True,headers={"User-Agent":DEFAULT_USERAGENT})
        if 300 > session.status_code >= 200:
            data = session.json()
            with open(DIRECTORIES.DRIVERCHECKSOURCE,"w") as wops:
                json.dump(data,wops,indent=4)
            ReturnInitialInfo(f"LOLBAS DRIVER DATA HAS BEEN SAVED TO {DIRECTORIES.DRIVERCHECKSOURCE}")
        else:
            ReturnInitialInfo("LOLBAS DRIVER DATA IS NOT AVAILABLE FOR NOW")
    if isUpdate:
        url = "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.json"
        session = requests.get(url,verify=False,timeout=100,allow_redirects=True,stream=True,headers={"User-Agent":DEFAULT_USERAGENT})
        if 300 > session.status_code >= 200:
            data = session.json()
            with open(DIRECTORIES.DIGITALSIDEURLSOURCE,"w") as wops:
                json.dump(data,wops,indent=4)
            ReturnInitialInfo(f"DIGITAL SIDE LATEST DOMAINS DATA HAS BEEN SAVED TO {DIRECTORIES.DIGITALSIDEURLSOURCE}")
        else:
            ReturnInitialInfo("DIGITAL SIDE LATEST DOMAINS DATA IS NOT AVAILABLE FOR NOW")
    if isUpdate:
        url = "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"
        session = requests.get(url,verify=False,timeout=100,allow_redirects=True,stream=True,headers={"User-Agent":DEFAULT_USERAGENT})
        if 300 > session.status_code >= 200:
            data = session.text
            ipListAll = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',data)
            with open(DIRECTORIES.DIGITALSIDEIPSOURCE,"w") as wops:
                json.dump(ipListAll,wops,indent=4)
            ReturnInitialInfo(f"DIGITAL SIDE LATEST IPS DATA HAS BEEN SAVED TO {DIRECTORIES.DIGITALSIDEIPSOURCE}")
        else:
            ReturnInitialInfo("DIGITAL SIDE LATEST IPS DATA IS NOT AVAILABLE FOR NOW")
    if isUpdate:
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt"
        session = requests.get(url,verify=False,timeout=100,allow_redirects=True,stream=True,headers={"User-Agent":DEFAULT_USERAGENT})
        if 300 > session.status_code >= 200:
            data = session.text
            ipListAll = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',data)
            ipData = {"IPs":ipListAll}
            with open(DIRECTORIES.FEODOTRACKERSOURCE,"w") as wops:
                json.dump(ipData,wops,indent=4)
            ReturnInitialInfo(f"FEODOTRACKER C2 IP DATA HAS BEEN SAVED TO {DIRECTORIES.FEODOTRACKERSOURCE}")
        else:
            ReturnInitialInfo("FEODOTRACKER C2 IP DATA IS NOT AVAILABLE FOR NOW")
    if isUpdate:
        url = "https://urlhaus.abuse.ch/downloads/text/"
        session = requests.get(url,verify=False,timeout=100,allow_redirects=True,stream=True,headers={"User-Agent":DEFAULT_USERAGENT})
        if 300 > session.status_code >= 200:
            data = session.text
            ipListAll = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',data)
            ipData = {"IPs":ipListAll}
            with open(DIRECTORIES.URLHAUSSOURCE,"w") as wops:
                json.dump(ipData,wops,indent=4)
            ReturnInitialInfo(f"URLHAUS MALICIOUS IP DATA HAS BEEN SAVED TO {DIRECTORIES.URLHAUSSOURCE}")
        else:
            ReturnInitialInfo("URLHAUS MALICIOUS IP DATA IS NOT AVAILABLE FOR NOW")

def ControlResult(result:Type[str])->Type[None]:
    if result is not None:
        if len(result) > 0:
            print(pprint.pformat(result,indent=2,width=70,underscore_numbers=False,compact=True,sort_dicts=False))
        else:
            ReturnInitialInfo("NO RESULT")
    else:
        ReturnInitialInfo("NO RESULT")

def SaveAllResult(result:Type[dict],saveName:Type[str])->Union[bool,None]:
    if result is not None:
        if isinstance(result,dict):
            savePath = os.path.join(DIRECTORIES.RESULTPATH,f"{str(saveName)}_RESULT.json")
            with open(savePath,"w") as wops:
                json.dump(result,wops,indent=4,allow_nan=True)
            ReturnInitialInfo(f"RESULT HAS BEEN SAVED TO {savePath}")
            return True
        else:
            ReturnInitialInfo("IT IS NOT DICTIONARY TO SAVE")
            return None
    else:
        ReturnInitialInfo("NOTHING TO SAVE")
        return None


