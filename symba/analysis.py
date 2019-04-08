import logging

from angr import Project
from angr.analyses.cfg.cfg import CFG

from symba.types import *
from symba.triggers import TriggerSource, malware_source_config
from symba.procedures import GetSystemTime


class Symba(object):
    def __init__(self, binary: Path, angr_options: Options = {'auto_load_libs': False}):
        self._binary = binary
        self._angr_options = angr_options

        self._init_logging()
        self._init_angr_project()

        self.triggers = []

    def _init_logging(self):
        # TODO: specify log format
        pass

    def _init_angr_project(self):
        self.project = Project(
            self._binary, load_options=self._angr_options)

    def _register_trigger(self, trigger: TriggerSource):
        self.triggers.append(trigger)
        self.project.hook_symbol(trigger.symbol, trigger.model)

    def find_calling_points(self, symbols: Symbols = [], cfg_options: Options = {'show_progressbar': True}) -> CallingPoints:
        """For each symbol in input - or for every symbol, if no specified - retrieves addresses of basic blocks
        calling that symbol.
        Several techniques can be used to obtain the former. At the moment, the function generates a static CFG starting
        from the executable and it uses it to determine predecessors.

        Keyword Arguments:
            symbols {Symbols} -- a list of symbols strings (default: {[]})
            cfg_options {Options} -- Options passed to the CFG generation in angr (default: {{'show_progressbar': True}})

        Returns:
            CallingPoints -- A mapping of {Symbol: Calling Block address} to retrieve functions' predecessors
        """

        rets: CallingPoints = {}
        try:
            # TODO: encapsulate different techniques to find callpoints, CFG may be not enough
            cfg: CFG = self.project.analyses.CFG(**cfg_options)
            for address, function in cfg.functions.items():
                try:
                    if function.name in symbols or not symbols:
                        pred = next(
                            iter(cfg.functions.callgraph.predecessors(address))
                        )
                        rets[function.name] = pred
                except StopIteration:
                    # some nodes won't have predecessors - obv - do not panic.
                    pass
        except Exception as e:
            # TODO: logging must not be here
            l: logging.Logger = logging.getLogger("symba_analysis")
            l.log(logging.ERROR, f"{e}")
        return rets

    def analyse(self, triggers=[]):
        """Handles the executable analysis, extracting trigger conditions.
        If no triggers are specified, Symba will load a default configuration
        with Trigger Sources typically found in malware analysis.

        Keyword Arguments:
            triggers {Sources} - - A list of TriggerSource objects to direct analysis (default: {[]})
        """

        if not triggers:
            # TODO: load triggers from a dedicated module here instead of creating them here
            for source in malware_source_config:
                self._register_trigger(source)

        syms = [t.symbol for t in self.triggers]
        points = self.find_calling_points(symbols=syms)

        for a, f in points:
            print(f"{a:X} -> {f}")
