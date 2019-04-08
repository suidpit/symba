import typing

from symba.types import FunctionModel


malware_source_config = []


class TriggerSource(object):
    """
    Base class for trigger-condition sources.
    """

    def __init__(self, symbol: str, model: FunctionModel):
        self._symbol = symbol
        self._model = model

    @property
    def model(self):
        return self._model

    @property
    def symbol(self):
        return self._symbol


# * Right now, functionality is not implemented. Default configuration remains malware.


def register_source(config: str):
    """ Registers a new TriggerSource into malware config sources.
    """
    def wrapper(func):
        if config == "malware":
            sim_proc = func()
            malware_source_config.append(
                TriggerSource(sim_proc.__class__.__name__, sim_proc))
        return func
    return wrapper
