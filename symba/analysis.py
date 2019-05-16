import logging
from typing import List, Dict

from angr import Project, SimState
from angr.analyses.cfg.cfg import CFG

from symba.triggers import TriggerSource, malware_source_config
from symba.procedures import GetSystemTime
from symba.exploration import TriggerSeer


class Symba(object):
    def __init__(self, binary: str, angr_options: dict = {'auto_load_libs': False}):
        self._binary = binary
        self._angr_options = angr_options

        self._init_logging()
        self._init_angr_project()

        # The first time I generate a CFG, I save it for performance purpose.
        self.cfg = None
        self.triggers = []

    def _init_logging(self):
        self.l = logging.getLogger("symba.analysis")

    def _init_angr_project(self):
        self.project = Project(
            self._binary, load_options=self._angr_options)

    def _register_triggers(self, config):
        # TODO: Just a placeholder for future
        if "malware" in config:
            for source in malware_source_config:
                #! Fixing a strange bug in decorator which returns a tuple instead of class
                source.model = source.model[0]
                self.triggers.append(source)

    def find_calling_points(self, symbols: List[str] = [], cfg_options: dict = {'show_progressbar': True}) -> List[Dict[str, int]]:
        """For each symbol in input - or for every symbol, if no specified - retrieves addresses of basic blocks
        calling that symbol.
        Several techniques can be used to obtain the former. At the moment, the function generates a static CFG starting
        from the executable and it uses it to determine predecessors.

        Keyword Arguments:
            symbols {List[str]} -- a list of symbols strings, e.g. 'strncmp', 'printf', 'GetSystemTime' (default: {[]})
            cfg_options {dict} -- Options passed to the CFG generation in angr (default: {{'show_progressbar': True}})

        Returns:
            call_points -- A mapping {symbol : address of predecessor calling block}
        """

        call_points = {}
        try:
            # TODO: encapsulate different techniques to find callpoints, CFG may be not enough
            # CFG is generated just one time for every find_calling_points call.
            if not self.cfg:
                self.cfg: CFG = self.project.analyses.CFG(**cfg_options)
            for address, function in self.cfg.functions.items():
                try:
                    if function.name in symbols or not symbols:
                        pred = next(
                            iter(self.cfg.functions.callgraph.predecessors(address))
                        )
                        call_points[function.name] = pred
                except StopIteration:
                    # some nodes won't have predecessors - obv - do not panic.
                    pass
        except Exception as e:
            self.l.log(logging.ERROR, f"{e}")
        return call_points

    def track_variable(self, trigger: TriggerSource):
        """The current core of the analysis. Taints and tracks, in the context of a symbolic execution,
        values produced by the specified trigger source, recognizing states reached by constraining
        them, adding them to the TriggerSource object. In the future it should be able to combine triggers,
        use different techniques for exploration, and provide different termination criteria. Right now, it doesn't.

        Arguments:
            trigger {TriggerSource} -- Trigger Source to extract condition from.
        """

        # Which block is calling this function?
        res = self.find_calling_points([trigger.symbol])

        # Replace Win32 Library with our function summary.
        self.project.hook_symbol(trigger.symbol, trigger.model)

        # I am assuming just one starting block, for now.
        call_addr = res[trigger.symbol]
        b = self.project.factory.block(addr=call_addr)
        # Set symbolic execution start to block calling trigger symbol
        start_state = self.project.factory.entry_state(addr=b.addr)
        # Initialize a simulation manager. For now, no technique is used.
        sm = self.project.factory.simulation_manager(start_state)

        # The only termination criterion, right now, is -- up to the end.
        sm.use_technique(TriggerSeer(trigger.symbol))

        sm.run()

        for state in sm.deadended + sm.active:
            if trigger.is_triggered(state):
                trigger.states.append(state)

    def analyse(self, source_configs: List[str] = ["malware"]):
        """Handles the executable analysis pipeline, starts variable tracking,
        and extracts from symbolic states trigger conditions passed from configuration.
        If no configuration is specified, Symba will load a default configuration
        with Trigger Sources typically found in malware analysis.

        Keyword Arguments:
            source_configs {List[str]} - - A list of TriggerSource objects to direct analysis (default: {["malware"]})
        """

        self._register_triggers(source_configs)
        for trigger in self.triggers:
            # ? How to handle multiple triggers in the same symbolic execution reusing work already done?
            self.track_variable(trigger)
            # Extract trigger conditions solving and comparing constraints into trigger states
            trigger.load_conditions()

            # ! There shouldn't be duplicates in the conditions, which should be parsed before -- just cleaning for demo here
            print(set(frozenset(v[1].items())
                      for v in trigger.conditions.items()))
