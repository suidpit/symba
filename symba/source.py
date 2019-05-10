"""
A brand new class which is
so interesting: it represents
a TriggerSource, and it EXTENDS
SimProcedures! So cool so sexy.
"""
from angr import SimProcedure

from symba.configuration import sig, param


class TriggerSource(SimProcedure):
    """
    It will work as a charm.
    A TriggerSource receives in input
    A Symba function signature,
    and it models the run() function,
    which needs to be inherited by angr
    standard, accordingly.
    """

    def __init__(self, fsig: sig):
        self.name = fsig.name

    # angr asks, we please him.
    def run(self, *args):
        print(args)