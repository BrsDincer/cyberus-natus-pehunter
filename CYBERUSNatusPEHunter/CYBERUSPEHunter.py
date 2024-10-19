from modules.peFileMeta import GetFileMetadata
from modules.peFileSuspiciousImports import GetSuspiciousImports
from modules.peFileNormalImports import GetNormalImports
from modules.peFileSectionDetails import GetSectionDetails
from modules.peFileExports import GetExports
from modules.peFileDebug import GetDebugTypes
from modules.peFileRelocations import GetRelocations
from modules.peFileThreatLocalStorage import GetThreatLocalStorage
from modules.peFileResources import GetResources
from modules.peFileCertificate import GetCertificate
from modules.peFileYARARules import GetYARAFromFile,GetYARAFromFolder
from modules.peFileGeneral import GetGeneralInformation
from modules.peFileAntiVM import GetAntiVM
from modules.peFileOvarlay import GetOverlay
from modules.peFilePackerSignature import GetPackerSignature
from modules.peFileEntryPoint import GetEntryPoint
from modules.peFileStringBehaviour import GetStringBehaviour
from modules.peFileXORDeltaRatio import GetXORDeltaRatio
from modules.peFileSectionExtract import GetExtractSection
from modules.peFileInitialBinaryBehaviour import GetBinaryBehaviour
from modules.peFileInitialDriverBehaviour import GetDriverBehaviour
from modules.peFileFeodotrackerIPQuery import GetFeodoTrackerIP
from modules.peFileURLHausIPQuery import GetURLHausIP
from modules.peFileDigitalSideURLQuery import GetDigitalSideURL
from modules.peFileDigitalSideIPQuery import GetDigitalSideIP
from modules.peFileDigitalSideAPIQuery import GetDigitalSideAPI
from modules.peFileDomainsDBQuery import GetDomainsDBQuery
from modules.peFileIPGeolocationQuery import GetIPGeolocationQuery
from modules.peFileThreatFoxQuery import GetThreatFoxQuery
from modules.peFileLogicalString import GetLogicalString
from modules.peFilePII import GetPII
from modules.peFileDLLList import GetDLLList
from modules.peFileCapabilities import GetCapabilities
from utils.scriptDirectories import DIRECTORIES
from utils.scriptFunctions import ConvertPathFile,GetOnlineSigmaSource,GetIsFile,ReturnInitialInfo,UpdateResources,ControlResult,CreateDirectory,SaveAllResult
from utils.scriptDesign import GetSubHeaderFormat,PrintBaseHeader,GetConfigDirectories,GetWarningMessage,PrintUsageExamples
from argparse import RawTextHelpFormatter
import pefile,argparse,sys,time,warnings

warnings.filterwarnings(action="ignore",message="[CHECK PYTHON VERSION]")
warnings.filterwarnings(action="ignore",message="[ALREADY IMPORTED]",category=UserWarning)
warnings.filterwarnings(action="ignore",category=DeprecationWarning)
warnings.filterwarnings(action="ignore",category=FutureWarning)

parserBase = argparse.ArgumentParser(
    prog="CYBERUSPEHunter",
    description="PE STATIC ANALYZER",
    formatter_class=RawTextHelpFormatter,
    add_help=True,
    exit_on_error=True,
    epilog=GetConfigDirectories()
)

#parserBase.add_argument("-h","--help",required=False,action="store_false",help="How to use")
parserBase.add_argument("target",nargs="?",help="Target File for Static Analysis",default=None)
parserBase.add_argument("-u","--usage",required=False,action="store_true",help="Gathering metadata information")
parserBase.add_argument("-m","--metainfo",required=False,action="store_true",help="Gathering metadata information")
parserBase.add_argument("-p","--pii",required=False,action="store_true",help="Gathering PII")
parserBase.add_argument("-sI","--simport",required=False,action="store_true",help="Gathering suspicious imports")
parserBase.add_argument("-nI","--nimport",required=False,action="store_true",help="Gathering normal imports")
parserBase.add_argument("-se","--sections",required=False,action="store_true",help="Gathering section details")
parserBase.add_argument("-ex","--exports",required=False,action="store_true",help="Gathering exports")
parserBase.add_argument("-dbg","--debugs",required=False,action="store_true",help="Gathering debugs")
parserBase.add_argument("-dll","--dlllist",required=False,action="store_true",help="Gathering debugs")
parserBase.add_argument("-rlc","--relocations",required=False,action="store_true",help="Gathering relocations")
parserBase.add_argument("-rsc","--resources",required=False,action="store_true",help="Gathering resources")
parserBase.add_argument("-tls","--threatlocalstorage",required=False,action="store_true",help="Gathering threat local storage")
parserBase.add_argument("-crt","--certificate",required=False,action="store_true",help="Gathering certificate")
parserBase.add_argument("-yFile","--yaraFile",required=False,dest="yaraFile",help="Gathering yara rules from file")
parserBase.add_argument("-yFolder","--yaraFolder",required=False,dest="yaraFolder",help="Gathering yara rules from folder")
parserBase.add_argument("-gen","--general",required=False,action="store_true",help="Gathering general information")
parserBase.add_argument("-avm","--antivmbehaviour",required=False,action="store_true",help="Gathering anti virtual machine behaviour")
parserBase.add_argument("-ovr","--overlay",required=False,action="store_true",help="Gathering overlay")
parserBase.add_argument("-pSig","--packersignature",required=False,action="store_true",help="Gathering packer signature")
parserBase.add_argument("-ep","--entrypoint",required=False,action="store_true",help="Gathering entry point")
parserBase.add_argument("-strBehav","--strbehaviour",required=False,action="store_true",help="Gathering general string behaviour")
parserBase.add_argument("-strLogic","--strlogical",required=False,action="store_true",help="Gathering general string behaviour")
parserBase.add_argument("-xor","--xorratio",required=False,action="store_true",help="Gathering XOR ratio")
parserBase.add_argument("-seExt","--sectionextraction",required=False,dest="sectionInit",help="Extraction of sections")
parserBase.add_argument("-binBehav","--binarybehaviour",required=False,action="store_true",help="Gathering binary behaviour")
parserBase.add_argument("-drvBehav","--drivebehaviour",required=False,action="store_true",help="Gathering drive behaviour")
parserBase.add_argument("-botIP","--botnetIP",required=False,action="store_true",help="Gathering botnet C2 IP by FeodoTracker")
parserBase.add_argument("-malIP","--maliciousIP",required=False,action="store_true",help="Gathering malicious IP by URLHaus")
parserBase.add_argument("-digURL","--digitalURL",required=False,action="store_true",help="Gathering malicious URL by Digital Side")
parserBase.add_argument("-digIP","--digitalIP",required=False,action="store_true",help="Gathering malicious IP by Digital Side")
parserBase.add_argument("-digAPI","--digitalAPI",required=False,action="store_true",help="Gathering IOC by Digital Side API")
parserBase.add_argument("-domDB","--domainDB",required=False,action="store_true",help="Gathering domain information by DomainDB API")
parserBase.add_argument("-geoIP","--geolocationIP",required=False,action="store_true",help="Gathering geolocation by IPGeolocation API")
parserBase.add_argument("-fox","--threatfox",required=False,action="store_true",help="Gathering IOC information by ThreatFox")
parserBase.add_argument("-capa","--capability",required=False,action="store_true",help="Gathering capabilities of imports")
parserBase.add_argument("-dsigma","--downloadsigma",required=False,dest="sigmaURL",help="Download Sigma rule")
parserBase.add_argument("-a","--all",required=False,action="store_true",help="Gathering IOC information by ThreatFox")
parserBase.add_argument("-sv","--save",required=False,dest="saveInit",default=False,help="Save results as json file")
parserBase.add_argument("-upd","--update",required=False,action="store_true",help="Updating sources")
args = parserBase.parse_args()

CreateDirectory(DIRECTORIES.CACHEPATH)
CreateDirectory(DIRECTORIES.SECTIONPATH)
CreateDirectory(DIRECTORIES.SIGMAPATH)
CreateDirectory(DIRECTORIES.LOGPATH)
CreateDirectory(DIRECTORIES.RESULTPATH)

PrintBaseHeader()
GetWarningMessage()
time.sleep(2)

targetFile = args.target
isSaved = args.saveInit

if not isinstance(isSaved,bool):
    if str(isSaved).lower() == "false":
        isSaved = False
    elif str(isSaved).lower() == "true":
        isSaved = True
    else:
        ReturnInitialInfo("UNEXPECTED INPUT DETECTED - USE True or False FOR SAVING")
        isSaved = False

if args.update:
    UpdateResources(isUpdate=True)
    sys.exit()

if args.sigmaURL:
    GetSubHeaderFormat("DOWNLOADING SIGMA")
    isSigma = GetOnlineSigmaSource(args.sigmaURL)
    sys.exit()

if args.usage:
    PrintUsageExamples()
    sys.exit()

if targetFile is not None:
    isTrueFile = GetIsFile(targetFile)
else:
    isTrueFile = False

if isTrueFile:
    fileEngine = open(targetFile,"rb")
    fileRaw = fileEngine.read()
    peEngine = pefile.PE(data=fileRaw,fast_load=True,max_repeated_symbol=120)
    peEngine.parse_data_directories()
    isPERead = True
else:
    isPERead = False

if isPERead:
    if args.all:
        GetSubHeaderFormat("GENERAL INFORMATION")
        generalInfo = GetGeneralInformation(peEngine,fileRaw)
        ControlResult(generalInfo)
        if isSaved:
            SaveAllResult(generalInfo,"GENERAL_INFO")
        #
        GetSubHeaderFormat("METADATA INFORMATION")
        retriesMeta = GetFileMetadata(peEngine)
        ControlResult(retriesMeta)
        if isSaved:
            SaveAllResult(retriesMeta,"METADATA_INFO")
        #
        GetSubHeaderFormat("SUSPICIOUS IMPORTS")
        suspiciousImports = GetSuspiciousImports(peEngine)
        ControlResult(suspiciousImports)
        if isSaved:
            SaveAllResult(suspiciousImports,"SUSPICIOUS_IMPORT_INFO")
        #
        GetSubHeaderFormat("NORMAL IMPORTS")
        normalImports = GetNormalImports(peEngine)
        ControlResult(normalImports)
        if isSaved:
            SaveAllResult(normalImports,"NORMAL_IMPORT_INFO")
        #
        GetSubHeaderFormat("SECTIONS INFORMATIONS")
        sectionsInfo = GetSectionDetails(peEngine)
        ControlResult(sectionsInfo)
        if isSaved:
            SaveAllResult(sectionsInfo,"SECTION_INFO")
        #
        GetSubHeaderFormat("PII VALUES")
        ReturnInitialInfo("YOU MAY ENCOUNTER UNEXPECTED VALUES, PLEASE CHECK MANUALLY")
        piiInfo = GetPII(targetFile)
        ControlResult(piiInfo)
        if isSaved:
            SaveAllResult(piiInfo,"POTENTIAL_PII_INFO")
        #
        GetSubHeaderFormat("DLL LIST")
        dllInfo = GetDLLList(targetFile)
        ControlResult(dllInfo)
        if isSaved:
            SaveAllResult(dllInfo,"DLL_LIST_INFO")
        #
        GetSubHeaderFormat("EXPORTS")
        exportInfo = GetExports(peEngine)
        ControlResult(exportInfo)
        if isSaved:
            SaveAllResult(exportInfo,"EXPORT_INFO")
        #
        GetSubHeaderFormat("DEBUGS")
        debugInfo = GetDebugTypes(peEngine)
        ControlResult(debugInfo)
        if isSaved:
            SaveAllResult(debugInfo,"DEBUG_INFO")
        #
        GetSubHeaderFormat("RELOCATIONS")
        relocInfo = GetRelocations(peEngine)
        ControlResult(relocInfo)
        if isSaved:
            SaveAllResult(relocInfo,"RELOCATION_INFO")
        #
        GetSubHeaderFormat("RESOURCES")
        rscInfo = GetResources(peEngine)
        ControlResult(rscInfo)
        if isSaved:
            SaveAllResult(rscInfo,"RESOURCES_INFO")
        #
        GetSubHeaderFormat("THREAT LOCAL STORAGE")
        tlsInfo = GetThreatLocalStorage(peEngine)
        ControlResult(tlsInfo)
        if isSaved:
            SaveAllResult(tlsInfo,"TLS_INFO")
        #
        GetSubHeaderFormat("CERTIFICATE")
        crtInfo = GetCertificate(peEngine)
        ControlResult(crtInfo)
        if isSaved:
            SaveAllResult(crtInfo,"CERTIFICATE_INFO")
        #
        GetSubHeaderFormat("ANTI-VM BEHAVIOUR")
        antiVMInfo = GetAntiVM(fileRaw)
        ControlResult(antiVMInfo)
        if isSaved:
            SaveAllResult(antiVMInfo,"ANTIVM_INFO")
        #
        GetSubHeaderFormat("PACKER SIGNATURE")
        packerINfo = GetPackerSignature(peEngine)
        ControlResult(packerINfo)
        if isSaved:
            SaveAllResult(packerINfo,"PACKER_INFO")
        #
        GetSubHeaderFormat("ENTRY POINT")
        entryInfo = GetEntryPoint(peEngine)
        ControlResult(entryInfo)
        if isSaved:
            SaveAllResult(entryInfo,"ENTRY_INFO")
        #
        GetSubHeaderFormat("STRING BEHAVIOUR")
        strInfo = GetStringBehaviour(targetFile)
        ControlResult(strInfo)
        if isSaved:
            SaveAllResult(strInfo,"STRING_BEHAVIOUR_INFO")
        #
        GetSubHeaderFormat("LOGICAL STRINGS")
        strLogicInfo = GetLogicalString(targetFile)
        ControlResult(strLogicInfo)
        if isSaved:
            SaveAllResult(strLogicInfo,"STRING_LOGICAL_INFO")
        #
        GetSubHeaderFormat("XOR RATIO")
        xorInfo = GetXORDeltaRatio(peEngine)
        ControlResult(xorInfo)
        if isSaved:
            SaveAllResult(xorInfo,"XOR_RATIO_INFO")
        #
        GetSubHeaderFormat("BINARY BEHAVIOUR")
        bnrInfo = GetBinaryBehaviour(targetFile)
        ControlResult(bnrInfo)
        if isSaved:
            SaveAllResult(bnrInfo,"BINARY_BEHAVIOUR_INFO")
        #
        GetSubHeaderFormat("DRIVER BEHAVIOUR")
        drvInfo = GetDriverBehaviour(targetFile)
        ControlResult(drvInfo)
        if isSaved:
            SaveAllResult(drvInfo,"DRIVER_BEHAVIOUR_INFO")
        #
        GetSubHeaderFormat("CAPABILITIES")
        capaInfo = GetCapabilities(peEngine)
        ControlResult(capaInfo)
        if isSaved:
            SaveAllResult(capaInfo,"CAPABILITIES_INFO")
        #
        GetSubHeaderFormat("MALICIOUS IP DETECTION - URLHAUS")
        malIPInfo = GetURLHausIP(targetFile)
        ControlResult(malIPInfo)
        if isSaved:
            SaveAllResult(malIPInfo,"URLHAUS_MALICIOUS_IP_INFO")
        #
        GetSubHeaderFormat("DOMAIN INFORMATION - DOMAINSDB")
        domInfo = GetDomainsDBQuery(targetFile)
        ControlResult(domInfo)
        if isSaved:
            SaveAllResult(domInfo,"DOMAINSDB_DOMAIN_INFO")
        #
        GetSubHeaderFormat("MALICIOUS URL DETECTION - DIGITAL SIDE")
        malURLInfo = GetDigitalSideURL(targetFile)
        ControlResult(malURLInfo)
        if isSaved:
            SaveAllResult(malURLInfo,"DIGITALSIDE_MALICIOUS_URL_INFO")
        #
        GetSubHeaderFormat("MALICIOUS IP DETECTION - DIGITAL SIDE")
        malIPDigitalInfo = GetDigitalSideIP(targetFile)
        ControlResult(malIPDigitalInfo)
        if isSaved:
            SaveAllResult(malIPDigitalInfo,"DIGITALSIDE_MALICIOUS_IP_INFO")
        #
        GetSubHeaderFormat("IOC QUERY - DIGITAL SIDE")
        iocDigitalInfo = GetDigitalSideAPI(targetFile)
        ControlResult(iocDigitalInfo)
        if isSaved:
            SaveAllResult(iocDigitalInfo,"DIGITALSIDE_IOC_INFO")
        #
        GetSubHeaderFormat("GEOLOCATION INFORMATION - IP API")
        geoInfo = GetIPGeolocationQuery(targetFile)
        ControlResult(geoInfo)
        if isSaved:
            SaveAllResult(geoInfo,"IPAPI_GEO_INFO")
        #
        GetSubHeaderFormat("IOC INFORMATION - THREAT FOX")
        foxInfo = GetThreatFoxQuery(targetFile)
        ControlResult(foxInfo)
        if isSaved:
            SaveAllResult(foxInfo,"THREATFOX_IOC_INFO")
        sys.exit()

if isPERead:
    if args.metainfo:
        GetSubHeaderFormat("METADATA INFORMATION")
        retriesMeta = GetFileMetadata(peEngine)
        ControlResult(retriesMeta)
    if args.simport:
        GetSubHeaderFormat("SUSPICIOUS IMPORTS")
        suspiciousImports = GetSuspiciousImports(peEngine)
        ControlResult(suspiciousImports)
    if args.nimport:
        GetSubHeaderFormat("NORMAL IMPORTS")
        normalImports = GetNormalImports(peEngine)
        ControlResult(normalImports)
    if args.sections:
        GetSubHeaderFormat("SECTIONS INFORMATIONS")
        sectionsInfo = GetSectionDetails(peEngine)
        ControlResult(sectionsInfo)
    if args.exports:
        GetSubHeaderFormat("EXPORTS")
        exportInfo = GetExports(peEngine)
        ControlResult(exportInfo)
    if args.debugs:
        GetSubHeaderFormat("DEBUGS")
        debugInfo = GetDebugTypes(peEngine)
        ControlResult(debugInfo)
    if args.relocations:
        GetSubHeaderFormat("RELOCATIONS")
        relocInfo = GetRelocations(peEngine)
        ControlResult(relocInfo)
    if args.threatlocalstorage:
        GetSubHeaderFormat("THREAT LOCAL STORAGE")
        tlsInfo = GetThreatLocalStorage(peEngine)
        ControlResult(tlsInfo)
    if args.resources:
        GetSubHeaderFormat("RESOURCES")
        rscInfo = GetResources(peEngine)
        ControlResult(rscInfo)
    if args.certificate:
        GetSubHeaderFormat("CERTIFICATE")
        crtInfo = GetCertificate(peEngine)
        ControlResult(crtInfo)
    if args.yaraFile:
        GetSubHeaderFormat("YARA RULE FROM FILE")
        yaraFilePath = ConvertPathFile(str(args.yaraFile),"yara_rules")
        yrFileInfo = GetYARAFromFile(targetFile,yaraFilePath)
        ControlResult(yrFileInfo)
    if args.yaraFolder:
        GetSubHeaderFormat("YARA RULE FROM FOLDER")
        yaraFolderPath = ConvertPathFile("",str(args.yaraFolder))
        yrFolderInfo = GetYARAFromFolder(targetFile,yaraFolderPath)
        ControlResult(yrFolderInfo)
    if args.general:
        GetSubHeaderFormat("GENERAL INFORMATION")
        generalInfo = GetGeneralInformation(peEngine,fileRaw)
        ControlResult(generalInfo)
    if args.antivmbehaviour:
        GetSubHeaderFormat("ANTI-VM BEHAVIOUR")
        antiVMInfo = GetAntiVM(fileRaw)
        ControlResult(antiVMInfo)
    if args.overlay:
        GetSubHeaderFormat("OVERLAY")
        overlayInfo = GetOverlay(peEngine,isSaved=True)
        ControlResult(overlayInfo)
    if args.packersignature:
        GetSubHeaderFormat("PACKER SIGNATURE")
        packerINfo = GetPackerSignature(peEngine)
        ControlResult(packerINfo)
    if args.entrypoint:
        GetSubHeaderFormat("ENTRY POINT")
        entryInfo = GetEntryPoint(peEngine)
        ControlResult(entryInfo)
    if args.strbehaviour:
        GetSubHeaderFormat("STRING BEHAVIOUR")
        strInfo = GetStringBehaviour(targetFile)
        ControlResult(strInfo)
    if args.strlogical:
        GetSubHeaderFormat("LOGICAL STRINGS")
        strLogicInfo = GetLogicalString(targetFile)
        ControlResult(strLogicInfo)
    if args.xorratio:
        GetSubHeaderFormat("XOR RATIO")
        xorInfo = GetXORDeltaRatio(peEngine)
        ControlResult(xorInfo)
    if args.sectionInit:
        GetSubHeaderFormat("SECTION EXTRACTION")
        isExtracted = GetExtractSection(peEngine,sectionName=str(args.sectionInit))
    if args.binarybehaviour:
        GetSubHeaderFormat("BINARY BEHAVIOUR")
        bnrInfo = GetBinaryBehaviour(targetFile)
        ControlResult(bnrInfo)
    if args.drivebehaviour:
        GetSubHeaderFormat("DRIVER BEHAVIOUR")
        drvInfo = GetDriverBehaviour(targetFile)
        ControlResult(drvInfo)
    if args.botnetIP:
        GetSubHeaderFormat("BOTNET C2 IP DETECTION - FEODOTRACKER")
        c2IPInfo = GetFeodoTrackerIP(targetFile)
        ControlResult(c2IPInfo)
    if args.maliciousIP:
        GetSubHeaderFormat("MALICIOUS IP DETECTION - URLHAUS")
        malIPInfo = GetURLHausIP(targetFile)
        ControlResult(malIPInfo)
    if args.digitalURL:
        GetSubHeaderFormat("MALICIOUS URL DETECTION - DIGITAL SIDE")
        malURLInfo = GetDigitalSideURL(targetFile)
        ControlResult(malURLInfo)
    if args.digitalIP:
        GetSubHeaderFormat("MALICIOUS IP DETECTION - DIGITAL SIDE")
        malIPDigitalInfo = GetDigitalSideIP(targetFile)
        ControlResult(malIPDigitalInfo)
    if args.digitalAPI:
        GetSubHeaderFormat("IOC QUERY - DIGITAL SIDE")
        iocDigitalInfo = GetDigitalSideAPI(targetFile)
        ControlResult(iocDigitalInfo)
    if args.domainDB:
        GetSubHeaderFormat("DOMAIN INFORMATION - DOMAINSDB")
        domInfo = GetDomainsDBQuery(targetFile)
        ControlResult(domInfo)
    if args.geolocationIP:
        GetSubHeaderFormat("GEOLOCATION INFORMATION - IP API")
        geoInfo = GetIPGeolocationQuery(targetFile)
        ControlResult(geoInfo)
    if args.threatfox:
        GetSubHeaderFormat("IOC INFORMATION - THREAT FOX")
        foxInfo = GetThreatFoxQuery(targetFile)
        ControlResult(foxInfo)
    if args.pii:
        GetSubHeaderFormat("PII VALUES")
        ReturnInitialInfo("YOU MAY ENCOUNTER UNEXPECTED VALUES, PLEASE CHECK MANUALLY")
        time.sleep(1)
        piiInfo = GetPII(targetFile)
        ControlResult(piiInfo)
    if args.dlllist:
        GetSubHeaderFormat("DLL LIST")
        dllInfo = GetDLLList(peEngine)
        ControlResult(dllInfo)
    if args.capability:
        GetSubHeaderFormat("CAPABILITIES")
        capaInfo = GetCapabilities(peEngine)
        ControlResult(capaInfo)
    sys.exit()
else:
    ReturnInitialInfo("TARGET FILE: NOT FOUND OR PATH IS INCORRECT")
    sys.exit()
