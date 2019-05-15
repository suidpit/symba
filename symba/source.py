from IPython import embed
"""
A brand new class which is
so interesting: it represents
what we GENERICALLY do
with functions to inject!
"""
import inspect

from angr import SimProcedure


class GenericModel(SimProcedure):
    """
    It will work as a charm.
    A GenericModel receives in input
    A Symba function signature,
    and it models the run() function
    just by injecting into memory
    symbols as specified into config,
    which needs to be inherited by angr
    standard, accordingly.
    """

    def __init__(self, fsig, config_name, default_len=32):
        self.fsig = fsig
        self.name = fsig.name
        self.config = config_name
        self.params = [inspect.Parameter(
            p.name, inspect.Parameter.POSITIONAL_OR_KEYWORD) for p in fsig.params]
        self._default_len = default_len

        super().__init__(num_args=len(self.params))
        pass

    # angr asks, we please him.
    def run(self, *args):  # pylint: disable=method-hidden
        # inspect.signature(self.run).bind(*args)
        params = self.fsig.params
        # Symbol Injection process
        for i, param in enumerate(params):
            if param.inject:
                # TODO: Model ARCH object to store these values (length, endianness)
                l = self._default_len if param.length == '<DEFAULT>' else param.length
                symbol = self.state.solver.BVS(
                    param.name,
                    l * 8,
                    key=(self.config, self.name, param.name),
                    eternal=True
                )
                # Order of params is quite important here!
                self.state.memory.store(
                    args[i], symbol, endness='Iend_BE' if "STR" in param.type else 'Iend_LE')
