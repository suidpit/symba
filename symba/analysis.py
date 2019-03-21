from triggers import *

import logging
import sys

import angr
from IPython import embed

l = logging.getLogger('symba.analysis')
l.setLevel(logging.INFO)


class Symba(object):
    def __init__(self, executable, auto_load_libs=True):
        self._auto_load_libs = auto_load_libs
        self.executable = executable
        l.info("Loading executable inside analysis engine...")
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
            cfg = self.project.analyses.CFGFast(regions=[(
                self.project.loader.main_object.min_addr, self.project.loader.main_object.max_addr)], force_complete_scan=False)
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
        blocks = self.find_triggers(triggers)
        for block, trigger in zip(blocks, triggers):
            if trigger in globals():
                # ! UGLY, UGLY, UGLY way to handle this
                self.project.hook_symbol(trigger, globals()[trigger]())
                self._follow(block.addr)

    def _follow(self, addr):
        state = self.project.factory.blank_state(addr=addr)
        sm = self.project.factory.simulation_manager(state)

        embed()


symba = Symba(
    "/home/symba/dev/symba/resources/pocs/simple_date_console/bin/simple_date_console.exe")

symba.print_map()

symba.track(
    ["GetSystemTime", "GetSystemTimeAsFileTime"])
