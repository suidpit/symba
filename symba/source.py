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

        self.run = lambda *args: GenericModel.run(self, *args)
        self.run.__signature__ = inspect.Signature(self.params)
        super().__init__(num_args=len(self.params))

    # angr asks, we please him.
    def run(self, *args):  # pylint: disable=method-hidden
        inspect.signature(self.run).bind(*args)
        params = self.fsig.params
        # Symbol Injection process
        for i, param in enumerate(params):
            if param.inject:
                if param.length == '<DEFAULT>':
                    param.length = self._default_len
                symbol = self.state.solver.BVS(
                    param.name,
                    param.length * 8,
                    key=(self.config, self.name, param.name),
                    eternal=True
                )
                # Order of params is quite important here!
                self.state.memory.store(
                    args[i], symbol, endness=self.project.arch.memory_endness)
