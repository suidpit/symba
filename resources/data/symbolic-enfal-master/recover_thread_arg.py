import angr
import sys

import angr, logging
import claripy
import pdb
import simuvex
import resource

import struct

proj = angr.Project('enfal_vt.exe', load_options={'auto_load_libs':False})

start = 0x4014A3
avoid = 0x402472
end = 0x4023ED

data_addr = None
data_size = None

# list symbols
#for s in proj.loader.main_bin.imports:
#   print s + " => " + hex(proj.loader.main_bin.imports[s].rebased_addr)
#print proj._extern_obj._lookup_table
#sys.exit(1)

def dump_data(state):

    global data_addr
    global data_size

    assert data_addr is not None
    assert data_size is not None

    # fix some bytes manually
    """
     /* 3236 0xca4 */   char    ptr_sub_403C80;
     /* 3240 0xca8 */   char    ptr_sub_404300;
     /* 7168 0x1c00 */  char    ptr_sub_404EE0;
     /* 9728 0x2600 */  char    ptr_sub_4048A0;
    """
    state.memory.store(data_addr + 0xca4, claripy.Reverse(claripy.BVV(0x403C80, 32)), 4)
    state.memory.store(data_addr + 0xca8, claripy.Reverse(claripy.BVV(0x404300, 32)), 4)
    state.memory.store(data_addr + 0x1c00, claripy.Reverse(claripy.BVV(0x404EE0, 32)), 4)
    state.memory.store(data_addr + 0x2600, claripy.Reverse(claripy.BVV(0x4048A0, 32)), 4)

    with open('arg_data.bin', 'w') as output:
        for i in range(data_size):
            v = state.memory.load(data_addr + i, 1)

            if not state.se.symbolic(v):
                b = state.se.any_int(v)
            
            else:
                bb = state.se.any_n_int(v, 2)
                if len(bb) > 1:
                    b = 0x0
                else:
                    b = bb[0]        

            output.write(struct.pack('c', chr(b)))

    with open('arg_data.symbolic', 'w') as output:
        
        for i in range(data_size):
            v = state.memory.load(data_addr + i, 1)

            if not state.se.symbolic(v):
                b = state.se.any_int(v)
                output.write(str(b) + "\n")
            
            else:
                bb = state.se.any_n_int(v, 2)
                if len(bb) > 1:
                    output.write("symbolic\n")
                else:
                    b = bb[0]       
                    output.write(str(b) + "\n") 



class _malloc(simuvex.SimProcedure):
    def run(self, sim_size):

        self.argument_types = {0: simuvex.s_type.SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(sim_size)
        size = self.state.se.any_int(sim_size)

        """
        if self.state.se.symbolic(sim_size):
            size = self.state.se.max_int(sim_size)
            #print "Max size allocable: " + str(size)
            if size > self.state.libc.max_variable_size: 
                size = self.state.libc.max_variable_size # 128 if too big
        else:
            size = self.state.se.any_int(sim_size) * 8
        """

        addr = self.state.libc.heap_location

        global data_addr
        data_addr = addr

        global data_size
        data_size = size

        self.state.libc.heap_location += size
        print "_malloc: " + hex(size) + " => " + str(hex(addr))
        return addr

class GetSystemDirectoryA(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetSystemDirectoryA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, str_buf_ptr, str_buf_size):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeString()), 
                                1: simuvex.s_type.SimTypeLength(self.state.arch)}

        self.return_type = simuvex.s_type.SimTypeLength(self.state.arch)

        assert not self.state.se.symbolic(str_buf_ptr)
        assert not self.state.se.symbolic(str_buf_size)

        system_dir = 'C:\WINDOWS\system32' + chr(0)
        written_size = len(system_dir) - 1

        for i in range(written_size + 1):
            self.state.memory.store(str_buf_ptr + i, ord(system_dir[i]), 1)

        res_str = self.state.se.any_str(self.state.memory.load(str_buf_ptr, 128)).split('\x00')[0]
        print "GetSystemDirectoryA: " + str(str_buf_ptr) + " " + str(str_buf_size) + " => " + str(written_size)  + " [" + res_str + "]"
        return written_size

class lstrcatA(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(lstrcatA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, dst, src):

        self.argument_types = {0: self.ty_ptr(simuvex.s_type.SimTypeString()),
                               1: self.ty_ptr(simuvex.s_type.SimTypeString())}

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeString())

        assert not self.state.se.symbolic(dst)
        assert not self.state.se.symbolic(src)

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        strncpy = simuvex.SimProcedures['libc.so.6']['strncpy']

        dst_len = self.inline_call(strlen, dst)
        src_len = self.inline_call(strlen, src)

        assert type(dst_len.ret_expr) in (int, long) or not self.state.se.symbolic(dst_len.ret_expr)
        assert type(src_len.ret_expr) in (int, long) or not self.state.se.symbolic(src_len.ret_expr)

        ret_expr = self.inline_call(strncpy, dst + dst_len.ret_expr, src, src_len.ret_expr+1, src_len=src_len.ret_expr).ret_expr
        res_str = self.state.se.any_str(self.state.memory.load(dst, 128)).split('\x00')[0]
        print "lstrcatA: " + str(dst) + " " + str(src) + " => " + str(ret_expr) + " [" + res_str + "]"
        return dst

class lstrcpyA(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(lstrcpyA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, dst, src):

        self.argument_types = {0: self.ty_ptr(simuvex.s_type.SimTypeString()),
                               1: self.ty_ptr(simuvex.s_type.SimTypeString())}

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeString())

        assert not self.state.se.symbolic(dst)
        assert not self.state.se.symbolic(src)

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        strncpy = simuvex.SimProcedures['libc.so.6']['strncpy']
        src_len = self.inline_call(strlen, src)

        assert type(src_len.ret_expr) in (int, long) or not self.state.se.symbolic(src_len.ret_expr)

        ret_expr = self.inline_call(strncpy, dst, src, src_len.ret_expr+1, src_len=src_len.ret_expr).ret_expr
        res_str = self.state.se.any_str(self.state.memory.load(ret_expr, 128)).split('\x00')[0]
        print "lstrcpyA: " + str(dst) + " " + str(src) + " => " + str(ret_expr) + " [" + res_str + "]"
        return ret_expr

class GetProcAddress(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetProcAddress, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, h_module, str_func):

        self.argument_types = {0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
                               1: self.ty_ptr(simuvex.s_type.SimTypeString())}

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(str_func)
        
        str_func_int_hi = self.state.se.any_int(str_func) & 0xFFFF0000
        assert str_func_int_hi != 0 # ToDo: add support ordinal value 

        func_name = self.state.se.any_str(self.state.memory.load(str_func, 128)).split('\x00')[0]

        # NB: we assume unique function names across DLLs...
        assert func_name in proj.loader.main_bin.imports
        symbol = proj.loader.main_bin.imports[func_name]

        global api_hooks
        assert eval(func_name) in api_hooks

        ret_expr = symbol.addr      

        print "GetProcAddress: " + str(h_module) + " " + str(func_name) + " => " + hex(ret_expr)
        return ret_expr

class LoadLibraryA(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(LoadLibraryA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, dll_name_ptr):

        self.argument_types = {0: self.ty_ptr(simuvex.s_type.SimTypeString()), }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(dll_name_ptr)
        dll_name = self.state.se.any_str(self.state.memory.load(dll_name_ptr, 128)).split('\x00')[0]

        ret_expr = claripy.BVS('hmodule_' + dll_name, 32)      

        print "LoadLibraryA: " + str(dll_name) + " => " + str(ret_expr)
        return ret_expr

class WSAStartup(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(WSAStartup, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, wVersionRequested, lpWSAData):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)), 
                                1: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))}

        self.return_type = simuvex.s_type.SimTypeInt()

        ret_expr = claripy.BVV(0x0, 32)  
        print "WSAStartup: " + str(wVersionRequested) + " " + str(lpWSAData) + " => " + str(ret_expr)
        return ret_expr

class gethostname(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(gethostname, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, name, namelen):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeString()), 
                                1: simuvex.s_type.SimTypeLength(self.state.arch)}

        self.return_type = simuvex.s_type.SimTypeInt()

        assert not self.state.se.symbolic(name)

        host_name = '$machine_host_name' + chr(0)
        written_size = len(host_name) - 1

        for i in range(written_size + 1):
            self.state.memory.store(name + i, ord(host_name[i]), 1)

        res_str = self.state.se.any_str(self.state.memory.load(name, 128)).split('\x00')[0]

        ret_expr = claripy.BVV(0x0, 32)  
        print "gethostname: " + str(name) + " [" +  res_str + "] " + str(namelen) + " => " + str(ret_expr)
        return ret_expr

class WSACleanup(simuvex.SimProcedure):

    def run(self):

        self.argument_types = {}
        self.return_type = simuvex.s_type.SimTypeInt() # actually it is void...
        
        ret_expr = claripy.BVV(0x0, 32)  
        print "WSACleanup: => " + str(ret_expr)
        return ret_expr

class Netbios(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(Netbios, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, pcnb):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))}

        self.return_type = simuvex.s_type.SimTypeInt()

        ret_expr = claripy.BVS('netbios_result', 32)  
        print "Netbios: " + str(pcnb) + " => " + str(ret_expr)
        return ret_expr

class wsprintfA(simuvex.SimProcedure):

    def run(self, str_buf_ptr, str_format_ptr):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeString()),
                                1: self.ty_ptr(simuvex.s_type.SimTypeString()),}

        self.return_type = simuvex.s_type.SimTypeInt()

        res_str = self.state.se.any_str(self.state.memory.load(str_format_ptr, 128)).split('\x00')[0]

        write_str = res_str + '\x00'
        for i in range(len(write_str)):
            self.state.memory.store(str_buf_ptr + i, ord(write_str[i]), 1)

        ret_expr = claripy.BVS('wsprintfA_result_' + res_str, 32)  
        print "wsprintfA: " + str(str_buf_ptr) + " " + str(res_str) + " => " + str(ret_expr)
        return ret_expr

class GetModuleFileNameA(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetModuleFileNameA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 3

    def run(self, hModule, lpFilename, nSize):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)),
                                1: self.ty_ptr(simuvex.s_type.SimTypeString()),
                                2: simuvex.s_type.SimTypeInt() }

        self.return_type = simuvex.s_type.SimTypeInt()

        assert not self.state.se.symbolic(hModule)
        if self.state.se.any_int(hModule) == 0x0:
            res_str = "C:\\$path_to_binary" + '\x00'
        else:
            assert False # ToDo: not yet implemented

        for i in range(len(res_str)):
            self.state.memory.store(lpFilename + i, ord(res_str[i]), 1)

        ret_expr = len(res_str)  
        print "GetModuleFileName: " + str(hModule) + str(lpFilename) + "[" + res_str + "]" + str(nSize) + " => " + str(ret_expr)
        return ret_expr

class gethostbyname(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(gethostbyname, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, name):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeString()), }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(name)
        
        name_str = self.state.se.any_str(self.state.memory.load(name, 128)).split('\x00')[0]
        
        #edx 0x0F02000A
        #eax 0x012165BC

        ret_expr = claripy.BVS('result_gethostbyname', 32) 
        print "gethostbyname: " + str(name) + "[" + name_str + "]" + " => " + str(ret_expr)
        return ret_expr

class inet_ntoa(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(inet_ntoa, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, addr):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)), }

        self.return_type = self.ty_ptr(simuvex.s_type.SimTypeString())
        
        addr = 0xABCDE124
        ip_addr = "192.168.1.1" + '\x00'

        for i in range(len(ip_addr)):
            self.state.memory.store(addr + i, ord(ip_addr[i]), 1)
        
        ret_expr = 0xABCDE124
        print "inet_ntoa: " + str(addr) + " => " + str(ret_expr) + "[" + ip_addr + "]"
        return ret_expr

class GetVersionExA(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetVersionExA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpVersionInfo):

        self.argument_types = { 0: self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch)), }

        self.return_type = simuvex.s_type.SimTypeInt()
        
        # Windows XP
        self.state.memory.store(lpVersionInfo + 4, 0x5, 4)                
        self.state.memory.store(lpVersionInfo + 8, 0x5, 4)
        self.state.memory.store(lpVersionInfo + 16, 0x2, 4)

        ret_expr = claripy.BVV(0x1, 32);
        print "GetVersionExA: " + str(lpVersionInfo) + " => " + str(ret_expr)
        return ret_expr

class GetACP(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetACP, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 0

    def run(self):

        self.argument_types = { }

        self.return_type = simuvex.s_type.SimTypeInt()
        
        ret_expr = claripy.BVV(1252, 32);
        print "GetACP: => " + str(ret_expr)
        return ret_expr

class GetLocaleInfoA(simuvex.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetLocaleInfoA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 4

    def run(self, Locale, LCType, lpLCData, cchData):

        self.argument_types = { 0: simuvex.s_type.SimTypeInt(),
                                1: simuvex.s_type.SimTypeInt(),
                                2: self.ty_ptr(simuvex.s_type.SimTypeString()),
                                3: simuvex.s_type.SimTypeInt()}

        self.return_type = simuvex.s_type.SimTypeInt()

        locale_str = "0409" + '\x00'

        for i in range(len(locale_str)):
            self.state.memory.store(lpLCData + i, ord(locale_str[i]), 1)
        
        ret_expr = claripy.BVV(5, 32);
        print "GetLocaleInfoA: => " + str(ret_expr)
        return ret_expr

api_hooks = {   GetSystemDirectoryA : None, 
                lstrcatA : None, 
                lstrcpyA : None, 
                _malloc : 0x4060DF, 
                GetProcAddress : None,
                LoadLibraryA : None,
                WSAStartup : None,
                gethostname : None,
                WSACleanup: None,
                Netbios: None,
                wsprintfA: None,
                GetModuleFileNameA: None,
                gethostbyname: None,
                inet_ntoa: None,
                GetVersionExA: None,
                GetACP: None,
                GetLocaleInfoA: None }

state = proj.factory.blank_state(addr=start, remove_options={simuvex.o.LAZY_SOLVES,})

# init registers
state.regs.ebx = proj.loader.main_bin.imports['GetSystemDirectoryA'].addr
state.regs.ecx = 0x0

# install api hooks
for api in api_hooks:
    addr = api_hooks[api]
    if addr is None:
        
        symbol = proj.loader.main_bin.imports[api.__name__] 
        addr = symbol.addr
        rebased_addr = symbol.rebased_addr

        # fix issue with indirect call
        state.memory.store(rebased_addr, claripy.Reverse(claripy.BVV(addr, 32)))

    # install hook
    proj.hook(addr, angr.project.Hook(api))

start_esp = state.regs.esp + 0x7A8

state.memory.store(0x0040E3AC, 0x0, 4)
state.memory.store(0x40E0B8, 0x0, 16)

with open('init_data.bin', 'r') as input:
    for line in input:
        
        line = line.rstrip('\n').split(' ')
        line = [x for x in line if len(x) > 0]

        addr = int(line[0].split(':')[1], 16)
        size = line[1]
        size = 1 if size == 'db' else (2 if size == 'dw' else 4) 
        data = int(line[-1].replace('h', ''), 16)

        state.memory.store(addr, claripy.Reverse(claripy.BVV(data, size * 8)), size)

pg = proj.factory.path_group(state, veritesting=False, ) # veritesting_options={'boundaries': _boundaries}s

k = 0
while len(pg.active) > 0:

    remove_from_active = []
    for p in pg.active:
        if p.state.ip.args[0] == end:
            dump_data(state)
            sys.exit(0)
        elif str(p.state.ip) == str(avoid):
            remove_from_active.append(p)

    for p in remove_from_active:
        pg.active.remove(p)

    if len(pg.active) > 1:
        pdb.set_trace()

    assert len(pg.active) == 1

    state = pg.active[0].state
    eip = hex(state.ip.args[0])

    if False and eip == hex(0x401552):
        pdb.set_trace()

    print "[" + str(k+1) + "] Executing at: " + eip + " stack_size=" + str(hex((start_esp - state.regs.esp).args[0]))

    pg.step(num_inst=1) #

    k += 1

print pg
pdb.set_trace()
print str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024) + " MB"
