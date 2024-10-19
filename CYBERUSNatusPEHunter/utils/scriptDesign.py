from utils.scriptDirectories import DIRECTORIES
from typing import Union,Type

def GetConfigDirectories()->Type[None]:
    confMessage = f"""

    
    BINARY SOURCE: {DIRECTORIES.BINARYCHECKSOURCE}
    DRIVER SOURCE: {DIRECTORIES.DRIVERCHECKSOURCE}
    FEODOTRACKER SOURCE: {DIRECTORIES.FEODOTRACKERSOURCE}
    DIGITAL SIDE LATEST DOMAIN SOURCE: {DIRECTORIES.DIGITALSIDEURLSOURCE}
    DIGITAL SIDE LATEST IPS SOURCE: {DIRECTORIES.DIGITALSIDEIPSOURCE}
    URL HAUS SOURCE: {DIRECTORIES.URLHAUSSOURCE}
    MATCH SOURCE: {DIRECTORIES.MATCHRESOURCE}
    SIGNATURE SOURCE: {DIRECTORIES.SIGNATURERESOURCE}


"""
    return confMessage

def GetWarningMessage()->Type[None]:
    print("\n")
    print("\t\t# CAREFUL ANALYSIS OF OUTPUT IS RECOMMENDED, WHEN IN DOUBT, REMEMBER TO CHECK MANUALLY #\t\t")
    print("\t\t# DON'T FORGET TO UPDATE RESOURCES BEFORE USING (--update) #\t\t")

def GetSubHeaderFormat(inputTitle:Type[str])->Type[None]:
    print("\n")
    print("".ljust(50,">"))
    print(str(inputTitle).upper())
    print("".ljust(50,"<"))

def PrintBaseHeader()->Union[None]:
    bannerMain = """


    ____ _   _ ___  ____ ____ _  _ ____
    |     \_/  |__] |___ |__/ |  | [__ 
    |___   |   |__] |___ |  \ |__| ___]

    _  _ ____ ___ _  _ ____
    |\ | |__|  |  |  | [__ 
    | \| |  |  |  |__| ___]

                
 A CTI-CYBER THREAT INTELLIGENCE PROJECT

 [ CYBERUSPEHunter - V:0.0.1 ]
 >>  PE STATIC ANALYZER
 
 """
    print(bannerMain)

def PrintUsageExamples()->Union[None]:
    usageOutput = """

    
    python .\CYBERUSPEHunter.py <TARGET_FILE> --all
    python .\CYBERUSPEHunter.py <TARGET_FILE> --all --save True
    python .\CYBERUSPEHunter.py <TARGET_FILE> --yaraFile url.yar
    python .\CYBERUSPEHunter.py <TARGET_FILE> --yaraFolder yara_rule
    python .\CYBERUSPEHunter.py <TARGET_FILE> -sI -nI -m
    python .\CYBERUSPEHunter.py <TARGET_FILE> --sections
    python .\CYBERUSPEHunter.py <TARGET_FILE> --sectionextraction all
    python .\CYBERUSPEHunter.py <TARGET_FILE> --sectionextraction text
    python .\CYBERUSPEHunter.py <TARGET_FILE> --downloadsigma 'https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_addinutil_uncommon_dir_exec.yml'
    

"""
    print(usageOutput)