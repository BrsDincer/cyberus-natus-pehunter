from utils.scriptUtilization import I_Directory
from typing import Type
import os

class DIRECTORIES:
    BASEPATH:Type[I_Directory] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    LOGPATH:Type[I_Directory] = os.path.join(BASEPATH,"log_source")
    RESULTPATH:Type[I_Directory] = os.path.join(BASEPATH,"result_source")
    SECTIONPATH:Type[I_Directory] = os.path.join(BASEPATH,"section_source")
    CACHEPATH:Type[I_Directory] = os.path.join(BASEPATH,"ds_cache")
    SIGMAPATH:Type[I_Directory] = os.path.join(BASEPATH,"sigma_rules")
    MATCHRESOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","matchresource.json")
    SIGNATURERESOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","signatureresource.txt")
    BINARYCHECKSOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","binarychecksource.json")
    DRIVERCHECKSOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","driverchecksource.json")
    FEODOTRACKERSOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","feodotrackeriplist.json")
    URLHAUSSOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","urlhausiplist.json")
    CAPABILITIESSOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","capabilitiessource.json")
    DIGITALSIDEURLSOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","digitalsidelatestdomains.json")
    DIGITALSIDEIPSOURCE:Type[I_Directory] = os.path.join(BASEPATH,"sources","digitalsidelatestips.json")