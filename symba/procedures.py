import claripy
import requests

from angr import SimProcedure

from symba.triggers import register_source
from symba.arch import Win32

# TODO: automatically generate stub functions from MSDN documentation
# TODO: Implement a generic class for Win32 API functions

################################
#   GetSystemTime
#   https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemtime
################################


@register_source("malware")
class GetSystemTime(SimProcedure):
    def __init__(self):
        # TODO: Move this to outer class
        self.os_arch = Win32()
        super().__init__()

    def run(self, lpSystemTime):
        start = lpSystemTime
        wordsize: int = self.os_arch.WORD

        # Init dict to store symbols stuff in
        self.state.globals['GetSystemTime'] = {}

        for word in [
                'wYear', 'wMonth', 'wDayOfWeek', 'wDay', 'wHour', 'wMinute',
                'wSecond', 'wMilliseconds'
        ]:
            word_symbol = claripy.BVS(word, wordsize * 8)
            self.state.memory.store(start,
                                    word_symbol,
                                    endness=self.project.arch.memory_endness)
            # TODO: new state plugin to store these injections instead of globals dict
            self.state.globals['GetSystemTime'][word] = word_symbol
            start += wordsize

        #! There's no constraint on validity of fields --> e.g. day can be higher than 31, and so on
        # * Ugly way to fix things while symbol injection is not handled by a plugin
        self.state.solver.add(
            self.state.globals['GetSystemTime']['wMonth'] <= 12)
        self.state.solver.add(
            self.state.globals['GetSystemTime']['wDay'] <= 31)
        return


@register_source('malware')
class GetUserNameA(SimProcedure):
    def __init__(self):
        self.os_arch = Win32()
        super().__init__()

    def run(self, lpBuffer, pcbBuffer):
        name_symbol = claripy.BVS("username",
                                  8 * self.state.mem[pcbBuffer].dword.concrete)
        self.state.memory.store(lpBuffer, name_symbol)

        self.state.globals['GetUserNameA'] = {}
        self.state.globals['GetUserNameA']['username'] = name_symbol
        return


# TODO Functions in list:
# Process32{First, Next}
# GetModuleFileName
# DeviceIoControl (for disk size)
# GetDiskFreeSpaceExA
# GetModuleHandle