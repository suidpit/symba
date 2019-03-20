from triggers import *

from collections import defaultdict

import logging
import sys

import angr
from IPython import embed

l = logging.getLogger('symba.analysis')
l.setLevel(logging.INFO)


class Symba(object):
    def __init__(self, executable, auto_load_libs=False):
        self._auto_load_libs = auto_load_libs
        self.executable = executable
        l.info("Loading executable inside analysis engine...")

        # Shut up those nasty logs
        logging.getLogger("angr").setLevel("CRITICAL")

        # TODO: check how auto load libs impacts loader mapping behaviour
        self.project = angr.Project(executable, load_options={
                                    'auto_load_libs': self._auto_load_libs})

    def print_map(self):
        """Prints a well-formatted memory map of the loaded executable, and imported libraries,
        if present.
        """
        loader = self.project.loader
        l.info(
            f"Loading object {loader.main_object} \nloading {loader.shared_objects}...")
        l.info(
            f"{loader.main_object} base address: {loader.main_object.min_addr}")

    def find_triggers(self, trigger_api):
        """Scans the binary code, looking for calls to trigger sources.

        Arguments:
            trigger_api {string} -- A list of symbols representing trigger sources.

        Returns:
            list -- A List of addresses pointing to precedessor states.
        """
        found = False
        addrs = []
        for symbol in trigger_api:
            if self.project.loader.find_symbol(symbol):
                l.info(
                    f"Executable is using {symbol} somewhere!")
                found = True
        if found:
            l.info("Generating CFG...")
            """cfg = self.project.analysolver
                regions=[(
                    self.project.loadersolver
                    self.project.loadersolver
                ],
                force_complete_scan=Falsolver
                symbols=True,
                resolve_indirect_jumps=solver
                show_progressbar=True)
            """
            cfg = self.project.analyses.CFGEmulated(
                show_progressbar=True
            )
            for address, function in cfg.functions.items():
                if function.name in trigger_api:
                    l.info(
                        f"0x{address:x} -> {function}\n  Import DLL: {function.binary_name}")
                    predecessors = next(iter(cfg.functions.callgraph.predecessors(
                        address)))
                    l.info(f"Called from function at 0x{predecessors:x}")
                    addrs.append(predecessors)

        return [self.project.factory.block(addr) for addr in addrs]

    def track(self, triggers: list):
        raw_data = {}
        blocks = self.find_triggers(triggers)

        # Collect simulations of tracked triggering variables
        for block, trigger in zip(blocks, triggers):
            if trigger in globals():
                # ! UGLY, UGLY, UGLY way to handle this
                self.project.hook_symbol(trigger, globals()[trigger]())
                stashes = self._follow(block.addr)
                raw_data[trigger] = stashes

        # Extract trigger conditions
        for trigger in triggers:
            if trigger in raw_data:
                constraints = self._extract_constraints(raw_data)
        return constraints

    def _follow(self, addr):
        state = self.project.factory.blank_state(addr=addr)
        sm = self.project.factory.simulation_manager(state)
        sm.run()
        return sm.stashes

    def export_constraints(self, trigger, trackings, tracked_stashes=[]):
        l.info(f"{trigger} variable tracking report:")

        tracked_stashes = trackings[trigger]
        if not tracked_stashes:
            tracked_stashes = [s for s in tracked_stashes.keys()]
        for stash in tracked_stashes:
            for c in tracked_stashes[stash]:
                state = c[0]
                sols = {}
                for sym in state.globals.keys():
                    # TODO: What with states not reached because of solver inability to decide matching inputs? Detect those scenarios;
                    sols[sym] = c[0].solver.eval(state.globals[sym])
                l.info(f"State {c[0]} is reached through:"
                       f"| wDay -> {sols['wDay']} | wMonth -> {sols['wMonth']} | wYear -> {sols['wYear']}")
                l.info(
                    "Maybe you should try to setup your environment with these dates?")

    def _extract_constraints(self, data: defaultdict):
        rets = {}
        for trigger in data:
            rets[trigger] = {}
            for stash in data[trigger]:
                rets[trigger][stash] = []
                for state in data[trigger][stash]:
                    rets[trigger][stash].append(
                        (state, state.solver.constraints))
            return rets


symba = Symba(
    "/home/symba/dev/symba/resources/pocs/simple_date_console/bin/simple_date_console_mingw.exe", auto_load_libs=True)

trackings = symba.track(["GetSystemTime"])

if "GetSystemTime" in trackings:
    symba.export_constraints("GetSystemTime", trackings)
