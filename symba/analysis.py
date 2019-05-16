import logging

from pprint import pprint, pformat
from typing import List, Dict

from angr import Project, SimState
from angr.analyses.cfg.cfg import CFG

from symba.configuration import SymbaConfig
from symba.triggers import TriggerSource, malware_source_config
from symba.exploration import TriggerSeer
from symba.exceptions import SymbaMissingSource


class Symba(object):
    def __init__(self,
                 binary: str,
                 config_paths: List[str] = ['malware.json'],
                 angr_options: dict = {'auto_load_libs': False}):
        self._binary = binary
        self._angr_options = angr_options
        self._config_paths = config_paths

        # The first time I generate a CFG, I save it for performance purpose.
        self.cfg = None
        self.triggers = []

        self._init_logging()
        self._init_angr_project()
        self._init_configuration()
        pass

    def _init_logging(self):
        self.l: logging.Logger = logging.getLogger("symba.analysis")
        self.l.setLevel(logging.INFO)

    def _init_angr_project(self):
        self.project = Project(self._binary, load_options=self._angr_options)

    def _init_configuration(self):
        for config in self._config_paths:
            for model in SymbaConfig(config).models:
                self.triggers.append(TriggerSource(model))

    """
    def _register_triggers(self, config):
        # TODO: Just a placeholder for future
        if "malware" in config:
            for source in malware_source_config:
                #! Fixing a strange bug in decorator which returns a tuple instead of class
                source.model = source.model[0]
                self.triggers.append(source)
    """

    def find_calling_points(self,
                            symbols: List[str] = [],
                            cfg_options: dict = {'show_progressbar': True}
                            ) -> List[Dict[str, int]]:
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
                self.l.debug((address, function.name))
                try:
                    if function.name in symbols or not symbols:
                        self.l.info(f"Intercepted call to {function.name}")
                        pred = next(
                            iter(
                                self.cfg.functions.callgraph.predecessors(
                                    address)))
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
        res = self.find_calling_points([trigger.name])

        # If there is no calling point, the function won't be called in binary.
        if not res:
            raise SymbaMissingSource

        # Replace Win32 Library with our function summary.
        self.project.hook_symbol(trigger.name, trigger.model)

        # I am assuming just one starting block, for now.
        call_addr = res[trigger.name]
        b = self.project.factory.block(addr=call_addr)
        # Set symbolic execution start to block calling trigger symbol
        start_state = self.project.factory.entry_state(addr=b.addr)
        # Initialize a simulation manager. For now, no technique is used.
        sm = self.project.factory.simulation_manager(start_state)

        sm.use_technique(TriggerSeer(
            (trigger.model.config, trigger.model.name)))

        sm.run()

        # TODO: Differentiate trigger conditions on state? Makes sense!
        for state in sm.deadended + sm.active + sm.unconstrained:
            if trigger.is_triggered(state):
                trigger.states.append(state)

    def analyse(self):
        """Handles the executable analysis pipeline, starts variable tracking,
        and extracts from symbolic states trigger conditions passed from configuration.
        If no configuration is specified, Symba will load a default configuration
        with Trigger Sources typically found in malware analysis.
        """
        """
        self._register_triggers(source_configs)
        """
        brutto_result = ""
        for trigger in self.triggers:
            try:
                # ? How to handle multiple triggers in the same symbolic execution reusing work already done?
                self.track_variable(trigger)
                # Extract trigger conditions solving and comparing constraints into trigger states
                trigger.load_conditions()

                # ! There shouldn't be duplicates in the conditions, which should be parsed before -- just cleaning for demo here
                # ! Define where to print, now this is just throwing output in logs.
                # TODO: Implement clean() and format() on TriggerCondition
                brutto_result += pformat(set(
                    frozenset(v[1].items())
                    for v in trigger.conditions.items()))
            except SymbaMissingSource:
                continue
        with open("out.log", 'w') as f:
            f.write(brutto_result + '\n')
