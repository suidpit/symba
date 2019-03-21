
from arch import DATA_TYPES

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
            self.state.memory.store(start, claripy.BVS(word, wordsize*8))
            start += wordsize
        from IPython import embeds
        return
