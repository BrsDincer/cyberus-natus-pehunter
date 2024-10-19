from utils.scriptUtilization import I_Error,I_Class
from typing import Type,Union

class Errors(object):
    def __init__(self,error:Type[I_Error],message:Union[str,I_Class]=NotImplemented)->Type[I_Class]:
        self.__error = error
        self.__message = message
    def __call__(self)->Type[I_Error]:
        raise self.__error(self.__message)
    def __getstate__(self)->Type[I_Error]:
        raise self.__error(self.__message)
    def __len__(self)->Type[int]:
        return 0
    def __str__(self)->Type[str]:
        return "CUSTOM ERROR MODULATION - INTERNAL CLASS"
    def __repr__(self)->Type[str]:
        return Errors.__doc__
    def ManuelError(self,errorType:Type[I_Error],errorMessage:Union[str,I_Class])->Type[I_Error]:
        raise errorType(errorMessage)