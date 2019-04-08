
from .arch import DATA_TYPES

from angr import SimProcedure
import claripy

################################
#   GetSystemTime
################################


class GetSystemTime(SimProcedure):

    def run(self, lpSystemTime):
        start = lpSystemTime
        wordsize: int = DATA_TYPES["Windows"]["WORD"]

        for word in ['wYear', 'wMonth', 'wDayOfWeek', 'wDay']:
            word_symbol = claripy.BVS(word, wordsize*8)
            self.state.memory.store(
                start, word_symbol, endness=self.project.arch.memory_endness)
            self.state.globals[word] = word_symbol

            start += wordsize

        self.state.solver.add(self.state.globals['wDay'] <= 31)
        from IPython import embed
        return
