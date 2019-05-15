import typing

from collections import defaultdict

from angr import SimProcedure, SimState
from claripy import BV


class TriggerSource(object):
    """
    Base class for trigger-condition sources.
    """

    def __init__(self, symbol: str, model: SimProcedure):
        self.symbol = symbol
        self.model = model
        # Our state-plugin, state-globals free list storing symbol keys
        self._keys = [(model.config_name, model.name, param.name) for param in model.fsig.params if param.inject]
        self.states = []
        self.conditions = defaultdict(dict)

    def _is_constrained(self, bv: BV, state: SimState):
        return any(not bv.variables.isdisjoint(constraint.variables)
                   for constraint in state.solver.constraints)

    def _get_constrained(self, state):
        # This rets must be a TriggerCondition or something like this.
        # We need an explicit mapping between symbol and name that the API will expect to solve symbol.
        rets = {}
        # Iterate over every variable injected by trigger sources in each state
        for key, symbol in state.solver.get_variables():
            if self._is_constrained(symbol, state):
                rets[key] = symbol
        return rets

    # ? Is this really useful for performances?
    def is_triggered(self, state):
        """
        Returns True if state is dependent on the trigger source,
        False otherwise.
        """
        # * Right now, this is obtained by scanning the list
        # * of constraints looking for injected symbols appearing there.
        return any(
            self._is_constrained(variable[1], state)
            for variable in state.solver.get_variables())

    #! This MUST DISAPPEAR
    def load_conditions(self):
        for s in self.states:
            cvars = self._get_constrained(s)
            for name, sym in cvars.items():
                self.conditions[s][name] = s.solver.eval(sym, cast_to=bytes)


malware_source_config = []


def register_source(config: str):
    """
    Registers a new TriggerSource into malware config sources.
    """

    def wrapper(func):
        if config == "malware":
            sim_proc = func()
            malware_source_config.append(
                TriggerSource(sim_proc.__class__.__name__, sim_proc))
        return sim_proc

    return wrapper
