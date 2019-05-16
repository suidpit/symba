from abc import ABC

from angr import SimState
from typing import Tuple, List
from claripy import BV

class TriggerCondition(ABC):
    """
    An interface for conditions to extract
    from binaries. A TriggerCondition
    is represented by:
    - A solve() method which collects
    a set of states and constraints
    and extract a meaningful set of constraints,
    opportunally cast.
    - A clean() method to trim/remove
    unnecessary data -- not printable bytes in strings,
    unconstrained solves.
    - An export() method which takes an exporter method
    to take out constraints (to log files, images, or sandboxes
    config files).
    """

    def __init__(self, variable: Tuple(Tuple(str, str), BV), states: List[SimState]):
        pass
