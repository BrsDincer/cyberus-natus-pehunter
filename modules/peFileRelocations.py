from utils.scriptUtilization import I_Class
from utils.scriptFunctions import ReturnInitialError,ReturnInitialInfo
from typing import Union,Type

def GetRelocations(peRaw:Type[I_Class])->Union[dict,None]:
    relocations = {}
    if hasattr(peRaw,"OPTIONAL_HEADER"):
        if hasattr(peRaw.OPTIONAL_HEADER,"DATA_DIRECTORY"):
            for dirInit in peRaw.OPTIONAL_HEADER.DATA_DIRECTORY:
                if str(dirInit.name).rstrip() == "IMAGE_DIRECTORY_ENTRY_BASERELOC":
                    break
                else:
                    pass
            if str(dirInit.name).rstrip() == "IMAGE_DIRECTORY_ENTRY_BASERELOC":
                dirVirtualAddress = dirInit.VirtualAddress
                dirSize = dirInit.Size
                relocDirectories = peRaw.parse_relocations_directory(dirVirtualAddress,dirSize)
                idx = 0
                initialItems = {}
                if len(relocDirectories) > 0:
                    try:
                        for items in relocDirectories:
                            idx += 1
                            if len(items.entries) > 0:
                                for _ in items.entries:
                                    initialItems.update(
                                        {
                                            f"RELOC_{str(idx)}_LENGTH":len(items.entries)
                                        }
                                    )
                            else:
                                pass
                    except Exception as err:
                        ReturnInitialError(err)
                    if len(initialItems) > 0:
                        relocations.update(
                            {
                                "DETAILS":initialItems
                            }
                        )
                    else:
                        pass
                    results = relocations if len(relocations) > 0 else None
                    return results
                else:
                    ReturnInitialInfo("NO RELOCATION DIRECTORY")
                    return None
            else:
                ReturnInitialInfo("NOT ENTRY BASERELOC")
                return None
        else:
            ReturnInitialInfo("NO DATA DIRECTORY")
            return None
    else:
        ReturnInitialInfo("NO OPTIONAL HEADER")
        return None