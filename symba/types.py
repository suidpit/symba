"""
Just bookkeeping some type for now. I still have to decide up to which point
I want to maintain static typing before growing this one.
"""

from typing import List, Dict

from angr import SimProcedure

#from symba.triggers import TriggerSource


class Path(str):
    """
    Path in filesystem.
    """
    pass


class Options(dict):
    """
    key->value options to various plugins.
    """
    pass


"""
class Sources(List[TriggerSource]):
    """
# Triggering condition sources.
"""
    pass
"""


class Symbols(List[str]):
    """
    List of symbols embedded in binaries - e.g. 'strncmp', 'printf', 'GetSystemTimeAsFiletime'.
    """
    pass


class CallingPoints(Dict[str, int]):
    """
    (Symbol) -> (Address of block calling symbol) mapping retrieved analysing the CFG.
    """
    pass


class FunctionModel(SimProcedure):
    """
    A Function summary, used to model a given library without symbolic executing it.
    """
    pass
