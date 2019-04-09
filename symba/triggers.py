import typing

from angr import SimProcedure

# ? Should this extend SimProcedure?


class TriggerSource(object):
    """
    Base class for trigger-condition sources.
    """

    def __init__(self, symbol: str, model: SimProcedure):
        self.symbol = symbol
        self.model = model,
        self._constraints = {}
        self._states = []
        self.conditions = {}

    def _load_constraints(self, state):
        for var in state.globals(self.symbol):
            for constraint in state.solver.constraints:
                # if variable appears in constraint
                if not var.variables.isdisjoint(constraint.variables):
                    if not self._constraints[self.symbol]:
                        self._constraints[self.symbol] = []
                    self._constraints[self.symbol].append(var)

    @property
    def states(self):
        return self._states

    def extract_conditions(self):
        for state in self._states:
            self._load_constraints(state)


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
