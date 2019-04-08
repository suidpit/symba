import claripy

from angr import SimProcedure

from symba.triggers import register_source
from symba.arch import Win32

################################
#   GetSystemTime
################################


@register_source("malware")
class GetSystemTime(SimProcedure):

    def run(self, lpSystemTime):
        w32 = Win32()
        start = lpSystemTime
        wordsize: int = w32.WORD

        for word in ['wYear', 'wMonth', 'wDayOfWeek', 'wDay', 'wHour', 'wMinute', 'wSeconds']:
            word_symbol = claripy.BVS(word, wordsize*8)
            self.state.memory.store(
                start, word_symbol, endness=self.project.arch.memory_endness)
            # TODO: new state plugin to store these injections
            self.state.globals[word] = word_symbol

            start += wordsize

        return
