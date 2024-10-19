from utils.scriptUtilization import I_Class
from utils.scriptFunctions import GetFileMagic,ReturnInitialError,ReturnInitialInfo,IsMagicPE
from typing import Union,Type
import pefile

def GetResources(peRaw:Type[I_Class])->Union[dict,None]:
    resources = {}
    if hasattr(peRaw,"DIRECTORY_ENTRY_RESOURCE"):
        idx = 0
        if hasattr(peRaw.DIRECTORY_ENTRY_RESOURCE,"entries"):
            try:
                for ent in peRaw.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        if hasattr(ent,"struct"):
                            #print(ent.struct)
                            entName = ent.struct.Name
                            #print(entName)
                            if entName is not None:
                                resourceName = ent.struct.Name
                            else:
                                resourceName = pefile.RESOURCE_TYPE.get(ent.struct.Id)
                            if resourceName is None:
                                resourceName = ent.struct.Id
                            else:
                                pass
                        else:
                            resourceName = None
                        if hasattr(ent,"directory"):
                            for idEnt in ent.directory.entries:
                                if hasattr(idEnt,"directory"):
                                    for rsc in idEnt.directory.entries:
                                        idx += 1
                                        dataRsc = peRaw.get_data(rsc.data.struct.OffsetToData,rsc.data.struct.Size)
                                        dataType = GetFileMagic(dataRsc)
                                        isPE = IsMagicPE(dataRsc[:8])
                                        if isPE:
                                            isExecutable = True
                                        else:
                                            isExecutable = False
                                        langRsc = pefile.LANG.get(rsc.data.lang,"UNKNOWN")
                                        subLangRsc = pefile.get_sublang_name_for_lang(rsc.data.lang,rsc.data.sublang)
                                        resources[idx] = {
                                            "RESOURCE_TYPE":str(resourceName).rstrip(),
                                            "OFFSET":rsc.data.struct.OffsetToData,
                                            "SIZE":rsc.data.struct.Size,
                                            "EXECUTABLE":isExecutable,
                                            "TYPE":dataType,
                                            "LANGUAGE":langRsc,
                                            "SUB_LANGUAGE":subLangRsc
                                        }
                                else:
                                    pass
                        else:
                            pass
                    except:
                        pass
            except Exception as err:
                ReturnInitialError(err)
            results = resources if len(resources) > 0 else None
            return results
        else:
            ReturnInitialInfo("NO ENTRIES")
            return None
    else:
        ReturnInitialInfo("NO DIRECTORY ENTRY RESOURCE")
        return None