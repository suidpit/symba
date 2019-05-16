import angr
import claripy
import sys
import pdb
import json

proj = None
api_hooks = None
verbose = True

class WinApiCallAction:

    _next_id = 1

    def __init__(self, addr, name, args = [], retval = [], objects = [], tid = 0):
        self._id = WinApiCallAction._next_id
        WinApiCallAction._next_id = WinApiCallAction._next_id + 1
        self._addr = addr
        self._name = name
        self._args = args if type(args) in (list,) else [args]
        self._retval = retval if type(retval) in (list,) else [retval]
        self._objects = objects if type(objects) in (list,) else [objects]
        self.state = None
        self._tid = tid if tid is not None else 0

    def dump_obj(self, buf):

        if type(buf) in (str,) or buf is None:
            return buf

        if len(buf) < 64:
            return self.state.se.min_int(buf)

        res = []

        if len(buf) <= 128 * 8:
            B = buf.chop(8)
        else:
            B = buf.get_bytes(0, min(len(buf) / 8, 128)).chop(8)

        B.reverse()
        constraints = ()
        k = 0
        for b in B:
            # ask min value to be consistent among different traces
            v = self.state.se.min_int(b, extra_constraints=constraints)
            res.append(v)
            constraints = constraints + (b == v,)

            # too memory intensive
            # self.state.se.add(b == v)

            print "Concretizing: " + str(k+1) + "/" + str(len(B))
            k += 1

        res.reverse()
        return res

    def expr_obj(self, buf):

        if type(buf) in (str,) or buf is None:
            return None

        if len(buf) < 64 and not buf.symbolic and len(buf) < 64:
            return self.state.se.any_int(buf)

        res = []

        if len(buf) <= 128 * 8:
            B = buf.chop(8)
        else:
            B = buf.get_bytes(0, min(len(buf) / 8, 128)).chop(8)

        for b in B:
            if not b.symbolic:
                b = self.state.se.any_int(b)
            else:
                b = str(b)
            res.append(b)

        return res

    def get_label_obj(self, obj, objs):

        if type(obj) in (list,):
            if len(obj) == 0:
                return None, objs

            obj = obj[0]

        if type(obj) in (int, long):
            return obj, objs
        else:
            # if obj is plain symbolic object use its label as label
            # otherwise use a fake label

            if hasattr(obj, 'args') and not obj.symbolic and obj.size <= 64:
                return self.state.se.any_int(obj), objs

            if hasattr(obj, 'args') and obj.symbolic and type(obj.args[0]) in (str,):
                label = "<" + obj.args[0] + ">"
            else:
                label = "<O" + str(len(objs)) + ">"
            objs[label] = obj
            return label, objs

    def __str__(self):

        objs = {}   # all symbolic objects

        args = []
        for arg in self._args:
            arg, objs = self.get_label_obj(arg, objs)
            args.append(arg)

        retval, objs = self.get_label_obj(self._retval, objs)

        other_objs = []
        for o in self._objects:
            o, objs = self.get_label_obj(o, objs)
            other_objs.append(o)

        objs_dump = {}
        for label in objs:
            o = objs[label]
            objs_dump[label] = self.dump_obj(o)

        objs_expr = {}
        for label in objs:
            o = objs[label]
            expr = self.expr_obj(o)
            if expr is not None:
                objs_expr[label] = expr

        data =  {
                "id": self._id,
                "addr": hex(int(self._addr, 16)),
                "api_name": self._name,
                "args": args,
                "retval": retval,
                "extra_objs": other_objs,
                "objs_expr": objs_expr,
                "objs_dump": objs_dump,
                "tid": self._tid,
               }

        s = json.dumps(data)
        return s

def get_symbol(func_name):

    global proj
    symbol = None

    # NB: we assume unique function names across DLLs...
    if func_name in proj.loader.main_bin.imports:
        symbol = proj.loader.main_bin.imports[func_name]

    elif func_name in proj._extern_obj._symbol_cache:
         symbol = proj._extern_obj._symbol_cache[func_name] 

    else:
        global verbose
        if verbose: print "Missing win32 model for " + func_name
        sys.exit(1)

    return symbol

class _malloc(angr.SimProcedure):
    def run(self, sim_size):

        self.argument_types = {0: angr.sim_type.SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(sim_size)
        size = self.state.se.any_int(sim_size)

        addr = self.state.libc.heap_location
        self.state.libc.heap_location += size

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, size, addr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return addr

class GetSystemDirectoryA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetSystemDirectoryA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, str_buf_ptr, str_buf_size):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()), 
                                1: angr.sim_type.SimTypeLength(self.state.arch)}

        self.return_type = angr.sim_type.SimTypeLength(self.state.arch)

        assert not self.state.se.symbolic(str_buf_ptr)
        assert not self.state.se.symbolic(str_buf_size)

        system_dir = 'C:\WINDOWS\system32' + chr(0)
        written_size = len(system_dir) - 1

        for i in range(written_size + 1):
            self.state.memory.store(str_buf_ptr + i, ord(system_dir[i]), 1)

        res_str = self.state.se.any_str(self.state.memory.load(str_buf_ptr, 128)).split('\x00')[0]

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [str_buf_ptr, str_buf_size], written_size, [system_dir], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return written_size

class lstrcatA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(lstrcatA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, dst, src):

        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()),
                               1: self.ty_ptr(angr.sim_type.SimTypeString())}

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeString())

        assert not self.state.se.symbolic(dst)
        assert not self.state.se.symbolic(src)

        strlen = angr.SimProcedures['libc.so.6']['strlen']
        strncpy = angr.SimProcedures['libc.so.6']['strncpy']

        dst_len = self.inline_call(strlen, dst)
        src_len = self.inline_call(strlen, src)

        assert type(dst_len.ret_expr) in (int, long) or not self.state.se.symbolic(dst_len.ret_expr)
        assert type(src_len.ret_expr) in (int, long) or not self.state.se.symbolic(src_len.ret_expr)

        ret_expr = self.inline_call(strncpy, dst + dst_len.ret_expr, src, src_len.ret_expr+1, src_len=src_len.ret_expr).ret_expr
        src_str = self.state.se.any_str(self.state.memory.load(src, 128)).split('\x00')[0]
        dst_str = self.state.se.any_str(self.state.memory.load(dst, 128)).split('\x00')[0]

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [dst, src], dst, [dst_str, src_str], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return dst

class lstrcpyA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(lstrcpyA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, dst, src):

        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()),
                               1: self.ty_ptr(angr.sim_type.SimTypeString())}

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeString())

        assert not self.state.se.symbolic(dst)
        assert not self.state.se.symbolic(src)

        strlen = angr.SimProcedures['libc.so.6']['strlen']
        strncpy = angr.SimProcedures['libc.so.6']['strncpy']
        src_len = self.inline_call(strlen, src)

        assert type(src_len.ret_expr) in (int, long) or not self.state.se.symbolic(src_len.ret_expr)

        ret_expr = self.inline_call(strncpy, dst, src, src_len.ret_expr+1, src_len=src_len.ret_expr).ret_expr

        src_str = self.state.se.any_str(self.state.memory.load(src, 128)).split('\x00')[0]
        dst_str = self.state.se.any_str(self.state.memory.load(ret_expr, 128)).split('\x00')[0]

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [dst, src], ret_expr, [dst_str, src_str], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetProcAddress(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetProcAddress, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, h_module, lpProcName):

        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                               1: self.ty_ptr(angr.sim_type.SimTypeString())}

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpProcName)
        
        str_func_int_hi = self.state.se.any_int(lpProcName) & 0xFFFF0000
        assert str_func_int_hi != 0 # ToDo: add support ordinal value 

        func_name = self.state.se.any_str(self.state.memory.load(lpProcName, 128)).split('\x00')[0]

        symbol = get_symbol(func_name)

        global api_hooks
        assert eval(func_name) in api_hooks

        ret_expr = symbol.addr

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [h_module, lpProcName], ret_expr, [func_name], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class LoadLibraryA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(LoadLibraryA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, dll_name_ptr):

        self.argument_types = {0: self.ty_ptr(angr.sim_type.SimTypeString()), }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(dll_name_ptr)
        dll_name = self.state.se.any_str(self.state.memory.load(dll_name_ptr, 128)).split('\x00')[0]

        ret_expr = claripy.BVS('hmodule_' + dll_name, 32)    
        self.state.se.add(ret_expr != 0)  

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, dll_name_ptr, ret_expr, [dll_name], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class WSAStartup(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(WSAStartup, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, wVersionRequested, lpWSAData):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)), 
                                1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))}

        self.return_type = angr.sim_type.SimTypeInt()
        ret_expr = 0x0

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [wVersionRequested, lpWSAData], ret_expr, [None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class gethostname(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(gethostname, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, name, namelen):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()), 
                                1: angr.sim_type.SimTypeLength(self.state.arch)}

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(name)

        host_name = '$machine_host_name' + chr(0)
        written_size = len(host_name) - 1

        for i in range(written_size + 1):
            self.state.memory.store(name + i, ord(host_name[i]), 1)

        res_str = self.state.se.any_str(self.state.memory.load(name, 128)).split('\x00')[0]
        ret_expr = 0x0

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [name, namelen], ret_expr, [res_str], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class WSACleanup(angr.SimProcedure):

    def run(self):

        self.argument_types = {}
        self.return_type = angr.sim_type.SimTypeInt() # actually it is void...
        
        ret_expr = 0x0

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class Netbios(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(Netbios, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, pcnb):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))}

        self.return_type = angr.sim_type.SimTypeInt()
        ret_expr = claripy.BVS('netbios_result', 32)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [pcnb], ret_expr, [None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class wsprintfA(angr.SimProcedure):

    def run(self, str_buf_ptr, str_format_ptr):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()),
                                1: self.ty_ptr(angr.sim_type.SimTypeString()),}

        self.return_type = angr.sim_type.SimTypeInt()

        res_str = self.state.se.any_str(self.state.memory.load(str_format_ptr, 128)).split('\x00')[0]

        write_str = res_str + '\x00'
        for i in range(len(write_str)):
            self.state.memory.store(str_buf_ptr + i, ord(write_str[i]), 1)

        ret_expr = len(write_str)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [str_buf_ptr, str_format_ptr], ret_expr, [res_str, res_str], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetModuleFileNameA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetModuleFileNameA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 3

    def run(self, hModule, lpFilename, nSize):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                                1: self.ty_ptr(angr.sim_type.SimTypeString()),
                                2: angr.sim_type.SimTypeInt() }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(hModule)
        if self.state.se.any_int(hModule) == 0x0:
            res_str = "C:\\$path_to_binary" + '\x00'
        else:
            assert False # ToDo: not yet implemented

        for i in range(len(res_str)):
            self.state.memory.store(lpFilename + i, ord(res_str[i]), 1)

        ret_expr = len(res_str)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hModule, lpFilename], ret_expr, [res_str], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class gethostbyname(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(gethostbyname, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, name):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()), }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(name)
        
        name_str = self.state.se.any_str(self.state.memory.load(name, 128)).split('\x00')[0]
        ret_expr = claripy.BVS('result_gethostbyname', 32)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [name], ret_expr, [name_str], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class inet_ntoa(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(inet_ntoa, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, addr):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)), }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeString())
        
        addr = 0xABCDE124
        ip_addr = "192.168.1.1" + '\x00'

        for i in range(len(ip_addr)):
            self.state.memory.store(addr + i, ord(ip_addr[i]), 1)
        
        ret_expr = addr

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [addr], ret_expr, [ip_addr], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetVersionExA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetVersionExA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpVersionInfo):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)), }

        self.return_type = angr.sim_type.SimTypeInt()
        
        # Windows XP
        self.state.memory.store(lpVersionInfo + 4, 0x5, 4)                
        self.state.memory.store(lpVersionInfo + 8, 0x5, 4)
        self.state.memory.store(lpVersionInfo + 16, 0x2, 4)

        res = self.state.memory.load(lpVersionInfo, 20)
        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [lpVersionInfo], ret_expr, [res], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetACP(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetACP, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 0

    def run(self):

        self.argument_types = { }

        self.return_type = angr.sim_type.SimTypeInt()
        
        ret_expr = claripy.BVV(1252, 32)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetLocaleInfoA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetLocaleInfoA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 4

    def run(self, Locale, LCType, lpLCData, cchData):

        self.argument_types = { 0: angr.sim_type.SimTypeInt(),
                                1: angr.sim_type.SimTypeInt(),
                                2: self.ty_ptr(angr.sim_type.SimTypeString()),
                                3: angr.sim_type.SimTypeInt()}

        self.return_type = angr.sim_type.SimTypeInt()

        locale_str = "0409" + '\x00'

        for i in range(len(locale_str)):
            self.state.memory.store(lpLCData + i, ord(locale_str[i]), 1)
        
        ret_expr = claripy.BVV(5, 32)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [Locale, LCType, lpLCData, cchData], ret_expr, [locale_str], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class MessageBoxA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(MessageBoxA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 4

    def run(self, hWnd, lpText, lpCaption, uType):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                                1: self.ty_ptr(angr.sim_type.SimTypeString()),
                                2: self.ty_ptr(angr.sim_type.SimTypeString()),
                                3: angr.sim_type.SimTypeInt()}

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(lpText)
        assert not self.state.se.symbolic(lpCaption)

        lpText_str = self.state.se.any_str(self.state.memory.load(lpText, 128)).split('\x00')
        lpCaption_str = self.state.se.any_str(self.state.memory.load(lpCaption, 128)).split('\x00')

        ret_expr = claripy.BVS("result_MessageBoxA", 32);
        self.state.se.add(ret_expr != 0)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hWnd, lpText, lpCaption, uType], ret_expr, [lpText_str. lpCaption_str], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class htonl(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(htonl, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, hostlong):

        self.argument_types = { 0: angr.sim_type.SimTypeInt() }

        self.return_type = angr.sim_type.SimTypeInt()

        #assert not self.state.se.symbolic(hostlong)

        # win32 should be little endian
        ret_expr = claripy.Reverse(hostlong);

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hostlong], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class htons(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(htons, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, hostshort):

        self.argument_types = { 0: angr.sim_type.SimTypeShort() }

        self.return_type = angr.sim_type.SimTypeShort()

        #assert not self.state.se.symbolic(hostshort)

        # win32 should be little endian
        ret_expr = claripy.Reverse(hostshort);

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hostshort], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class ntohl(htonl):
    pass

class ntohs(htons):
    pass

class InternetOpenA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(InternetOpenA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 5

    def run(self, lpszAgent, dwAccessType, lpszProxyName, lpszProxyBypass, dwFlags):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()),
                                1: angr.sim_type.SimTypeInt(),
                                2: self.ty_ptr(angr.sim_type.SimTypeString()),
                                3: self.ty_ptr(angr.sim_type.SimTypeString()),
                                4: angr.sim_type.SimTypeInt() }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        ret_expr = claripy.BVS('hInternet', 32)
        self.state.se.add(ret_expr != 0)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [lpszAgent, dwAccessType, lpszProxyName, lpszProxyBypass, dwFlags], ret_expr, [None, None, None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class InternetOpenUrlA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(InternetOpenUrlA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 6

    def run(self, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):

        try:
            self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeString()),
                                    1: angr.sim_type.SimTypeInt(),
                                    2: self.ty_ptr(angr.sim_type.SimTypeString()),
                                    3: self.ty_ptr(angr.sim_type.SimTypeString()),
                                    4: angr.sim_type.SimTypeInt() }

            self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

            assert not self.state.se.symbolic(lpszUrl)
            url_str = self.state.se.any_str(self.state.memory.load(lpszUrl, 128)).split('\x00')[0]

            assert not self.state.se.symbolic(lpszHeaders)
            if self.state.se.any_int(lpszHeaders) == 0:
                header_str = None
            else:
                header_str = self.state.se.any_str(self.state.memory.load(lpszHeaders, 128)).split('\x00')[0]

            ret_expr = claripy.BVS('hInternet_url', 32)
            self.state.se.add(ret_expr != 0)

            api_name = self.__class__.__name__
            callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
            tid = self.state.rat.lookup('tid')
            a = WinApiCallAction(callsite, api_name, [hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext],
                                 ret_expr, [url_str, header_str], tid)
            self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

            global verbose
            if verbose: self.state.rat.print_last()
            return ret_expr

        except Exception as e:
            pdb.set_trace()

class InternetReadFile(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(InternetReadFile, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 4

    def run(self, hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(dwNumberOfBytesToRead)
        max_size = self.state.se.max_int(dwNumberOfBytesToRead)

        # make buffer symbolic
        buf = claripy.BVS('InternetReadFile_buffer', 8 * max_size)
        last_b = buf.get_byte(max_size - 1)
        self.state.se.add(last_b == 0x0)
        self.state.memory.store(lpBuffer, buf, max_size)

        assert not self.state.se.symbolic(lpdwNumberOfBytesRead)
        n_written = self.state.se.any_int(lpdwNumberOfBytesRead)
        nw = claripy.BVS('InternetReadFile_buffer_written', 32)
        self.state.se.add(nw <= max_size)
        self.state.memory.store(n_written, claripy.Reverse(nw))

        #print self.state.memory.load(lpBuffer, 10)
        #pdb.set_trace()

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead],
                             ret_expr, [buf, nw], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr


class InternetConnectA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(InternetConnectA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 8

    def run(self, hInternet, lpszServerName, nServerPort, lpszUsername, lpszPassword, dwService, dwFlags, dwContext):

        self.argument_types = { 0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                                1: self.ty_ptr(angr.sim_type.SimTypeString()),
                                2: angr.sim_type.SimTypeShort(),
                                3: self.ty_ptr(angr.sim_type.SimTypeString()),
                                4: self.ty_ptr(angr.sim_type.SimTypeString()),
                                5: angr.sim_type.SimTypeInt(),
                                6: angr.sim_type.SimTypeInt(),
                                7: self.ty_ptr(angr.sim_type.SimTypeInt()) }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpszServerName)
        if self.state.se.any_int(lpszServerName) != 0:
            server = self.state.se.any_str(self.state.memory.load(lpszServerName, 128)).split('\x00')[0]       
        else:
            server = None

        assert not self.state.se.symbolic(nServerPort)
        port = self.state.se.any_int(nServerPort)        

        assert not self.state.se.symbolic(lpszUsername)
        if self.state.se.any_int(lpszUsername) != 0:
            user = self.state.se.any_str(self.state.memory.load(lpszUsername, 128)).split('\x00')[0]       
        else:
            user = None

        assert not self.state.se.symbolic(lpszPassword)
        if self.state.se.any_int(lpszPassword) != 0:
            pw = self.state.se.any_str(self.state.memory.load(lpszPassword, 128)).split('\x00')[0]       
        else:
            pw = None

        ret_expr = claripy.BVS('hInternet_connect', 32)
        self.state.se.add(ret_expr != 0)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hInternet, lpszServerName, port, lpszUsername, lpszPassword, dwService, dwFlags, dwContext],
                             ret_expr, [server, user, pw], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr
    
class HttpOpenRequestA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(HttpOpenRequestA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 8

    def run(self, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: self.ty_ptr(angr.sim_type.SimTypeString()),
            3: self.ty_ptr(angr.sim_type.SimTypeString()),
            4: self.ty_ptr(angr.sim_type.SimTypeString()),
            5: self.ty_ptr(angr.sim_type.SimTypeString()),
            6: angr.sim_type.SimTypeInt(),
            7: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpszVerb)
        if self.state.se.any_int(lpszVerb) != 0:
            verb = self.state.se.any_str(self.state.memory.load(lpszVerb, 128)).split('\x00')[0]       
        else:
            verb = None

        assert not self.state.se.symbolic(lpszVersion)
        if self.state.se.any_int(lpszVersion) != 0:
            version = self.state.se.any_str(self.state.memory.load(lpszVersion, 128)).split('\x00')[0]       
        else:
            version = None

        assert not self.state.se.symbolic(lpszObjectName)
        if self.state.se.any_int(lpszObjectName) != 0:
            name = self.state.se.any_str(self.state.memory.load(lpszObjectName, 128)).split('\x00')[0]       
        else:
            name = None

        ret_expr = claripy.BVS('hInternet_HttpOpenRequestA', 32)
        self.state.se.add(ret_expr != 0)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name,
                             [hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferer, lplpszAcceptTypes, dwFlags, dwContext],
                             ret_expr, [verb, name, version, None, None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class HttpSendRequestA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(HttpSendRequestA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 5

    def run(self, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength):

        try:
            self.argument_types = {
                0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                1: self.ty_ptr(angr.sim_type.SimTypeString()),
                2: angr.sim_type.SimTypeInt(),
                3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                4: angr.sim_type.SimTypeInt(),
                }

            self.return_type = angr.sim_type.SimTypeInt()

            assert not self.state.se.symbolic(lpszHeaders)
            if self.state.se.any_int(lpszHeaders) != 0:
                headers = self.state.se.any_str(self.state.memory.load(lpszHeaders, 128)).split('\x00')[0]       
            else:
                headers = None

            assert not self.state.se.symbolic(dwHeadersLength)
            headers_len = self.state.se.any_int(dwHeadersLength) 

            optional_len = None
            if not self.state.se.symbolic(dwOptionalLength):
                optional_len = self.state.se.any_int(dwOptionalLength) 
            
            assert not self.state.se.symbolic(lpOptional)
            lpOptional = self.state.se.any_int(lpOptional)
            if lpOptional != 0:

                if optional_len is None:
                    l = 64
                else:
                    l = optional_len

                #optional = self.state.se.any_str(self.state.memory.load(lpOptional, l)).split('\x00')[0]
                optional = self.state.memory.load(lpOptional, l)
            else:
                #optional = None
                optional = self.state.memory.load(lpOptional, optional_len)

            ret_expr = claripy.BVS('hInternet_HttpOpenRequestA', 32)
            self.state.se.add(ret_expr != 0)

            api_name = self.__class__.__name__
            callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
            tid = self.state.rat.lookup('tid')
            a = WinApiCallAction(callsite, api_name,
                                 [hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength],
                                 ret_expr, [headers, optional], tid)
            self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

            global verbose
            if verbose: self.state.rat.print_last()
            return ret_expr

        except Exception as e:
            pdb.set_trace()

class HttpEndRequestA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(HttpEndRequestA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 4

    def run(self, hRequest, lpBuffersOut, dwFlags, dwContext):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name,
                             [hRequest, lpBuffersOut, dwFlags, dwContext],
                             ret_expr, [None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class InternetCloseHandle(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(InternetCloseHandle, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, hInternet):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name,
                             [hInternet],
                             ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class CreateMutexA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CreateMutexA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 3

    def run(self, lpMutexAttributes, bInitialOwner, lpName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: angr.sim_type.SimTypeInt(),
            2: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpName)
        if self.state.se.any_int(lpName) != 0:
            name = self.state.se.any_str(self.state.memory.load(lpName, 128)).split('\x00')[0]     
        else:
            name = None

        ret_expr = claripy.BVS('handle_mutex', 32)
        self.state.se.add(ret_expr != 0)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name,
                             [lpMutexAttributes, bInitialOwner, name], ret_expr, [None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class CloseHandle(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CloseHandle, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, hObject):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hObject], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class FindFirstFileA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(FindFirstFileA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, lpFileName, lpFindFileData):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpFileName)
        if self.state.se.any_int(lpFileName) != 0:
            name = self.state.se.any_str(self.state.memory.load(lpFileName, 32)).split('\x00')[0]  
            name_buf = self.state.memory.load(lpFileName, 32)      
        else:
            name = "NULL"
            name_buf = None

        self.state.memory.store(lpFindFileData, claripy.BVS('WIN32_FIND_DATA', 8 * 320))

        ret_expr = claripy.BVS('handle_first_file', 32)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [lpFileName, lpFindFileData], ret_expr, [name, name_buf], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr


class FindNextFileA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(FindNextFileA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, hFindFile, lpFindFileData):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        # no more file to search...

        ret_expr = 0x0

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hFindFile, lpFindFileData], ret_expr, [None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetLogicalDrives(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetLogicalDrives, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 0

    def run(self, ):

        self.argument_types = {}
        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x4 # only C drive

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetDriveTypeA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetDriveTypeA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpRootPathName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(lpRootPathName)
        if self.state.se.any_int(lpRootPathName) != 0:
            path = self.state.se.any_str(self.state.memory.load(lpRootPathName, 128)).split('\x00')[0]
        else:
            path = None

        ret_expr = 0x3

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [lpRootPathName], ret_expr, [path], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class FindClose(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(FindClose, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, hFindFile):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1

        self.state.rat.add_unique(self.__class__.__name__ + ' @ ' + hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0]), [hFindFile, ret_expr])

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hFindFile], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class WinExec(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(WinExec, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, lpCmdLine, uCmdShow):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: angr.sim_type.SimTypeInt(),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        cmd_buf = self.state.memory.load(lpCmdLine, 16)
        if not self.state.se.symbolic(lpCmdLine):
            cmd_buf = self.state.memory.load(lpCmdLine, 16)
            cmd = self.state.se.any_str(self.state.memory.load(lpCmdLine, 128)).split('\x00')[0]        
        else:
            cmd = None
            cmd_buf = self.state.memory.load(lpCmdLine, 16)

        ret_expr = 32  # success

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [lpCmdLine, uCmdShow], ret_expr, [cmd_buf], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class CreateProcessA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CreateProcessA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 10

    def run(self, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: angr.sim_type.SimTypeInt(),
            5: angr.sim_type.SimTypeInt(),
            6: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            7: self.ty_ptr(angr.sim_type.SimTypeString()),
            8: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            9: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(lpApplicationName)
        if self.state.se.any_int(lpApplicationName) != 0:
            app = self.state.memory.load(lpApplicationName, 128)
            #app = self.state.se.any_str(app).split('\x00')[0]
        else:
            app = None

        assert not self.state.se.symbolic(lpCommandLine)
        if self.state.se.any_int(lpCommandLine) != 0:
            cmd = self.state.memory.load(lpCommandLine, 128)
            #cmd = self.state.se.any_str(cmd).split('\x00')[0]
        else:
            cmd = None

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name,
                             [lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation],
                             ret_expr,
                             [app, cmd, None, None, None, None, None, None],
                             tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class DeleteFileA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(DeleteFileA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpFileName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(lpFileName)
        if self.state.se.any_int(lpFileName) != 0:
            file = self.state.memory.load(lpFileName, 128)
            #file = self.state.se.any_str(file).split('\x00')[0]
        else:
            file = "NULL"

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name,
                             [lpFileName], ret_expr, [file], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class CreateDirectoryA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CreateDirectoryA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, lpPathName, lpSecurityAttributes):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(lpPathName)
        if self.state.se.any_int(lpPathName) != 0:
            file = self.state.memory.load(lpPathName, 128)
            #file = self.state.se.any_str(file).split('\x00')[0]
        else:
            file = "NULL"

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name,
                             [lpPathName, lpSecurityAttributes], ret_expr, [file, None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class RemoveDirectoryA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(RemoveDirectoryA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, lpPathName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(lpPathName)
        if self.state.se.any_int(lpPathName) != 0:
            file = self.state.memory.load(lpPathName, 128)
            #file = self.state.se.any_str(file).split('\x00')[0]
        else:
            file = "NULL"

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [lpPathName], ret_expr, [file], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class MoveFileA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(MoveFileA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, lpExistingFileName, lpNewFileName):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(lpExistingFileName)
        if self.state.se.any_int(lpExistingFileName) != 0:
            src = self.state.memory.load(lpExistingFileName, 128)
            #src = self.state.se.any_str(src).split('\x00')[0]
        else:
            src = None

        assert not self.state.se.symbolic(lpNewFileName)
        if self.state.se.any_int(lpNewFileName) != 0:
            dst = self.state.memory.load(lpNewFileName, 128)
            #dst = self.state.se.any_str(dst).split('\x00')[0]
        else:
            dst = None

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [lpExistingFileName, lpNewFileName], ret_expr, [src, dst], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class TerminateThread(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(TerminateThread, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, hThread, dwExitCode):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: angr.sim_type.SimTypeInt(),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hThread, dwExitCode], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class Sleep(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(Sleep, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, dwMilliseconds):

        self.argument_types = {
            0: angr.sim_type.SimTypeInt(),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x0 # void

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [dwMilliseconds], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class RegOpenKeyExA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(RegOpenKeyExA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 5

    def run(self, hKey, lpSubKey, ulOptions, samDesired, phkResult):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeLong()

        assert not self.state.se.symbolic(lpSubKey)
        if self.state.se.any_int(lpSubKey) != 0:
            reg_name = self.state.se.any_str(self.state.memory.load(lpSubKey, 128)).split('\x00')[0]        
        else:
            reg_name = None

        ret_expr = 0x0 # ERROR_SUCCESS

        assert not self.state.se.symbolic(lpSubKey)
        hSubKey = claripy.BVS('hSubKey', 32)
        self.state.memory.store(lpSubKey, hSubKey.reversed, 4)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hKey, lpSubKey, ulOptions, samDesired, phkResult], ret_expr, [reg_name, hSubKey], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class RegSetValueExA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(RegSetValueExA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 6

    def run(self, hKey, lpValueName, Reserved, dwType, lpData, cbData):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeString()),
            2: angr.sim_type.SimTypeInt(),
            3: angr.sim_type.SimTypeInt(),
            4: angr.sim_type.SimTypeChar(),
            5: angr.sim_type.SimTypeInt(),
            }

        self.return_type = angr.sim_type.SimTypeLong()

        assert not self.state.se.symbolic(lpValueName)
        if self.state.se.any_int(lpValueName) != 0:
            value = self.state.memory.load(lpValueName, 128)
        else:
            value = None

        data = self.state.memory.load(lpData, 4) # correct only if type is dword

        ret_expr = 0x0 # ERROR_SUCCESS

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hKey, lpValueName, Reserved, dwType, lpData, cbData], ret_expr, [value, data], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class RegCloseKey(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(RegCloseKey, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 1

    def run(self, hKey):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeLong()

        ret_expr = 0x0 # ERROR_SUCCESS

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        a = WinApiCallAction(callsite, api_name, [hKey], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class CreateThread(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CreateThread, self).execute(state, successors, arguments, ret_to)

    def run(self, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId):

        try:
            self.argument_types = {
                0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                1: angr.sim_type.SimTypeLength(),
                2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
                4: angr.sim_type.SimTypeInt(),
                5: self.ty_ptr(angr.sim_type.SimTypeInt()),
                }

            self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

            ret_expr = claripy.BVS('handle_thread', 32)
            self.state.se.add(ret_expr != 0)

            assert not self.state.se.symbolic(lpStartAddress)
            code_addr = self.state.se.any_int(lpStartAddress)

            # sequential approach
            ret_addr = self.state.stack_pop() # remove ret addr
            global verbose
            if verbose: print "Return to caller at " + str(ret_addr)
            self.state.regs.esp += 4 * 6 # remove args
            new_state = self.state.copy()
            new_state.stack_push(lpParameter) 
            new_state.stack_push(ret_addr) # return to caller
            tid = self.state.rat.lookup('tid')
            tid = 0 if tid is None else tid
            new_state.rat.add("tid", tid + 1)
            self.state.project.hook(ret_addr, lambda s: s.rat.add("tid", s.rat.lookup('tid') - 1), replace=True)
            self.successors.add_successor(new_state, code_addr, new_state.se.true, 'Ijk_Call')
            self.returns = False

            api_name = self.__class__.__name__
            callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
            a = WinApiCallAction(callsite, api_name, [lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId],
                                 ret_expr,
                                 [None, code_addr, None, None],
                                 tid)
            self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

            global verbose
            if verbose: self.state.rat.print_last()
            return ret_expr

        except Exception as e:
            pdb.set_trace()

class CreateFileA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(CreateFileA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 7

    def run(self, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeString()),
            1: angr.sim_type.SimTypeInt(),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            4: angr.sim_type.SimTypeInt(),
            5: angr.sim_type.SimTypeInt(),
            6: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch))

        assert not self.state.se.symbolic(lpFileName)
        if self.state.se.any_int(lpFileName) != 0:
            name = self.state.se.any_str(self.state.memory.load(lpFileName, 128)).split('\x00')[0]
            #buf = self.state.memory.load(lpFileName, 10)
        else:
            name = "NULL"

        ret_expr = claripy.BVS('handle_file', 32)
        self.state.se.add(ret_expr != 0) # not NULL
        self.state.se.add(ret_expr != 0xFFFFFFFF) # not INVALID_HANDLE_VALUE

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        tid = 0 if tid is None else tid
        a = WinApiCallAction(callsite, api_name,
                             [lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile],
                             ret_expr,
                             [name, None,], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetFileSize(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetFileSize, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 2

    def run(self, hFile, lpFileSizeHigh):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = claripy.BVS('file_size', 32)
        self.state.se.add(ret_expr > 0)
        self.state.se.add(ret_expr < 0x100)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        tid = 0 if tid is None else tid
        a = WinApiCallAction(callsite, api_name, [hFile, lpFileSizeHigh], ret_expr, [None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetLastError(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetLastError, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 0

    def run(self):

        self.argument_types = {}

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = claripy.BVS('thread_last_error', 32)

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        tid = 0 if tid is None else tid
        a = WinApiCallAction(callsite, api_name, [], ret_expr, [], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr


class WriteFile(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(WriteFile, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 5

    def run(self, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        if not self.state.se.symbolic(nNumberOfBytesToWrite):
            size = self.state.se.any_int(nNumberOfBytesToWrite)
        else:
            size = 16

        assert not self.state.se.symbolic(lpBuffer)
        if self.state.se.any_int(lpBuffer) != 0:
            buffer_content = self.state.se.any_str(self.state.memory.load(lpBuffer, size)).split('\x00')      
        else:
            buffer_content = None

        # up to requested bytes are written
        b_written = claripy.BVS('WriteFile_bytes_written', 32)
        self.state.se.add(b_written <= nNumberOfBytesToWrite)
        self.state.se.add(b_written > 0)
        self.state.memory.store(lpNumberOfBytesWritten, claripy.Reverse(b_written))

        self.state.memory.store(lpNumberOfBytesWritten, claripy.Reverse(nNumberOfBytesToWrite))

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        tid = 0 if tid is None else tid
        a = WinApiCallAction(callsite, api_name, [hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped], ret_expr,
                             [buffer_content, b_written, None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class HttpQueryInfoA(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(HttpQueryInfoA, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 5

    def run(self, hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: angr.sim_type.SimTypeInt(),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            4: self.ty_ptr(angr.sim_type.SimTypeInt()),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        tid = 0 if tid is None else tid
        a = WinApiCallAction(callsite, api_name,
                             [hRequest, dwInfoLevel, lpvBuffer, lpdwBufferLength, lpdwIndex], ret_expr,
                             [None, None, None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class ReadFile(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(ReadFile, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 5

    def run(self, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: angr.sim_type.SimTypeInt(),
            3: self.ty_ptr(angr.sim_type.SimTypeInt()),
            4: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        assert not self.state.se.symbolic(nNumberOfBytesToRead)
        max_size = self.state.se.any_int(nNumberOfBytesToRead)

        buf = claripy.BVS('ReadFile_buffer', 8 * max_size)
        self.state.memory.store(lpBuffer, buf)

        assert not self.state.se.symbolic(lpNumberOfBytesRead)
        ptr = self.state.se.any_int(lpNumberOfBytesRead)

        if ptr != 0:        
                        
            addr = claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4))
            count = self.state.rat.lookup('ReadFile_' + str(addr))
            if count is None:
                self.state.rat.add('ReadFile_'
                 + str(addr), 1)
                b_read = claripy.BVS('ReadFile_bytes_written', 32)
                self.state.se.add(b_read <= max_size)
                self.state.se.add(b_read > 0)
                self.state.memory.store(lpNumberOfBytesRead, claripy.Reverse(b_read))
            else:
                b_read = claripy.BVV(0x0, 32)
                self.state.memory.store(lpNumberOfBytesRead, claripy.Reverse(b_read))

        ret_expr = 0x1 # SUCCESS

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        tid = 0 if tid is None else tid
        a = WinApiCallAction(callsite, api_name,
                             [hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped], ret_expr,
                             [buf, b_read, None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class GetFileTime(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(GetFileTime, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 4

    def run(self, hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        tid = 0 if tid is None else tid
        a = WinApiCallAction(callsite, api_name,
                             [hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime], ret_expr,
                             [None, None, None, None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr

class SetFileTime(angr.SimProcedure):

    def execute(self, state, successors=None, arguments=None, ret_to=None):
        super(SetFileTime, self).execute(state, successors, arguments, ret_to)
        state.regs.esp += 4 * 4

    def run(self, hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime):

        self.argument_types = {
            0: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            1: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            2: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            3: self.ty_ptr(angr.sim_type.SimTypeTop(self.state.arch)),
            }

        self.return_type = angr.sim_type.SimTypeInt()

        ret_expr = 0x1

        api_name = self.__class__.__name__
        callsite = hex(claripy.Reverse(self.state.memory.load(self.state.regs.esp, 4)).args[0] - 4)
        tid = self.state.rat.lookup('tid')
        tid = 0 if tid is None else tid
        a = WinApiCallAction(callsite, api_name,
                             [hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime], ret_expr, [None, None, None], tid)
        self.state.rat.add_unique(api_name + ' @ ' + callsite, a)

        global verbose
        if verbose: self.state.rat.print_last()
        return ret_expr