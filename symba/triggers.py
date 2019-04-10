import typing

from collections import defaultdict

from angr import SimProcedure, SimState
from claripy import BV


class TriggerCondition(object):
    """
    Class representing a trigger condition. What does it contain? A given environment
    or context variable which can represent some triggering fact.
    """

# ? Should this extend SimProcedure?


class TriggerSource(object):
    """
    Base class for trigger-condition sources.
    """

    def __init__(self, symbol: str, model: SimProcedure):
        self.symbol = symbol
        self.model = model,
        self._constrained = []
        self._states = []
        self._conditions = defaultdict(dict)

    def _is_constrained(self, bv: BV, state: SimState):
        return any(not bv.variables.isdisjoint(constraint.variables) for constraint in state.solver.constraints)

    def _get_constrained(self, state):
        # This rets must be a TriggerCondition or something like this.
        # We need an explicit mapping between symbol and name that the API will expect to solve symbol.
        rets = {}
        # Iterate over every variable injected by trigger sources in each state
        for name, var in state.globals[self.symbol].items():
            if self._is_constrained(var, state):
                rets[name] = var
        return rets

    # ? Is this really useful for performances?
    def is_triggered(self, state):
        """
        Returns True if state is dependent on the trigger source,
        False otherwise.
        """
        # * Right now, this is obtained by scanning the list
        # * of constraints looking for injected symbols appearing there.
        return any(self._is_constrained(variable, state) for variable in state.globals[self.symbol].values())

    @property
    def states(self):
        return self._states

    @property
    def conditions(self):
        return self._conditions

    def load_conditions(self):
        for s in self._states:
            cvars = self._get_constrained(s)
            for name, sym in cvars.items():
                self._conditions[s][name] = s.solver.eval(sym)


malware_source_config = []

# * Right now, multiple config functionality is not implemented. Default configuration remains malware.


def register_source(config: str):
    """ Registers a new TriggerSource into malware config sources.
    """
    def wrapper(func):
        if config == "malware":
            sim_proc = func()
            malware_source_config.append(
                TriggerSource(sim_proc.__class__.__name__, sim_proc))
        return sim_proc
    return wrapper
