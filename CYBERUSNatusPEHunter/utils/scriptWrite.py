from utils.scriptUtilization import I_Function,I_Null,I_Process,I_Class,I_Error
from utils.scriptDirectories import DIRECTORIES
from typing import Union,Type
import uuid,os

class WriteFunction(I_Function):
    def __init__(self,path:Union[str,None]=None)->Type[I_Class]:
        self.__ops = None
        self.__path = str(path) if path is not None else os.path.join(DIRECTORIES.RESULTPATH,f"{str(uuid.uuid4()).replace('-','_')}.txt")
    def __call__(self)->Type[I_Null]:
        return None
    def __getstate__(self)->Type[I_Error]:
        raise NotImplementedError(NotImplemented)
    def __len__(self)->Type[int]:
        return 0
    def __str__(self)->Type[str]:
        return "WRITING RESULT MODULATION - INTERNAL CLASS"
    def __repr__(self)->Type[str]:
        return WriteFunction.__doc__
    def WriteOn(self,text:Union[str,bytes])->Type[I_Process]:
        text = text if isinstance(text,str) else str(text)
        return self.__ops.write(text)
    def __enter__(self)->Type[I_Process]:
        self.__ops = open(self.__path,"w")
        return self.__ops
    def __exit__(self,e1:Type[I_Class],e2:Type[I_Class],e3:Type[I_Class])->Type[I_Process]:
        self.__ops.close()
    