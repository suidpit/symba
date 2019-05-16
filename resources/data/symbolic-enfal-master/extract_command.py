import angr
import cle
import claripy
import sys
import pdb

from cle.backends.pe.symbol import WinSymbol

import win32_models
import rat_log

proj = angr.Project('enfal_vt.exe', load_options={'auto_load_libs':False})

start = 0x402BB0
avoid = []
end = None

class ConcretizationMin(angr.concretization_strategies.SimConcretizationStrategy):
    def _concretize(self, memory, addr):
        return [self._min(memory, addr)]

class ConcretizationChecker(angr.concretization_strategies.SimConcretizationStrategy):
    def _concretize(self, memory, addr):
        pdb.set_trace()

state = proj.factory.blank_state(addr=start, remove_options={angr.options.LAZY_SOLVES}) # angr.options.CACHELESS_SOLVER

#state.memory.read_strategies.insert(0, ConcretizationChecker())
#state.memory.read_strategies.insert(0, ConcretizationMin())
#state.memory.write_strategies.insert(0, ConcretizationChecker())
#state.memory.write_strategies.insert(0, ConcretizationMin())

def write_on_buffer(state):
    pdb.set_trace()

#0x7ffd4c02
#state.inspect.b('mem_write', mem_write_address=0xabcd3b40, action=write_on_buffer)

rat_logger = rat_log.RatLogger()
state.register_plugin('rat', rat_logger)

# init memory
arg_addr = 0xABCD1234
with open('arg_data.symbolic', 'r') as input:
    
    k = 0
    for line in input:
        
        line = line.rstrip('\n')
        if line == 'symbolic':
            state.memory.store(arg_addr + k, claripy.Reverse(claripy.BVS('arg_unknown_' + str(k), 8)), 1)
        else:
            v = int(line)
            state.memory.store(arg_addr + k, claripy.Reverse(claripy.BVV(v, 8)), 1)

        k += 1

# init registers
state.memory.store(state.regs.esp + 4, claripy.Reverse(claripy.BVV(arg_addr, 32)), 4)

pg = proj.factory.simgr(state, veritesting=False) # veritesting_options={'boundaries': _boundaries}s

start_esp = state.regs.esp

additional_import_addr = 0xFFFF0000

# win32 models
api_hooks = {   win32_models.GetSystemDirectoryA : None, 
                win32_models.lstrcatA : None, 
                win32_models.lstrcpyA : None, 
                win32_models._malloc : 0x4060DF, 
                win32_models.GetProcAddress : None,
                win32_models.LoadLibraryA : None,
                win32_models.WSAStartup : None,
                win32_models.gethostname : None,
                win32_models.WSACleanup: None,
                win32_models.Netbios: None,
                win32_models.wsprintfA: None,
                win32_models.GetModuleFileNameA: None,
                win32_models.gethostbyname: None,
                win32_models.inet_ntoa: None,
                win32_models.GetVersionExA: None,
                win32_models.GetACP: None,
                win32_models.GetLocaleInfoA: None,
                win32_models.MessageBoxA: None,
                win32_models.htonl: None,
                win32_models.htons: None,
                win32_models.ntohl: None,
                win32_models.ntohs: None,
                win32_models.InternetOpenA: None,
                win32_models.InternetOpenUrlA: None,
                win32_models.InternetReadFile: None,
                win32_models.InternetConnectA: None,
                win32_models.HttpOpenRequestA: None,
                win32_models.HttpSendRequestA: None,
                win32_models.HttpEndRequestA: None,
                win32_models.InternetCloseHandle: None,
                win32_models.CreateMutexA: None,
                win32_models.CloseHandle: None,
                win32_models.FindFirstFileA: None,
                win32_models.FindNextFileA: None,
                win32_models.GetLogicalDrives: None,
                win32_models.GetDriveTypeA: None,
                win32_models.FindClose: None,
                win32_models.WinExec: None,
                win32_models.CreateProcessA : None,
                win32_models.DeleteFileA: None,
                win32_models.CreateDirectoryA: None,
                win32_models.RemoveDirectoryA: None,
                win32_models.MoveFileA: None,
                win32_models.TerminateThread: None,
                win32_models.Sleep: None,
                win32_models.RegOpenKeyExA: None,
                win32_models.RegSetValueExA: None,
                win32_models.RegCloseKey: None,
                win32_models.CreateThread: None,
                win32_models.CreateFileA: None,
                win32_models.GetFileSize: None,
                win32_models.GetLastError: None,
                win32_models.WriteFile: None,
                win32_models.HttpQueryInfoA: None,
                win32_models.ReadFile: None,
                win32_models.GetFileTime: None,
                win32_models.SetFileTime: None,} 

def rep_stosd(state): 

    print "\tDoing a rep stdosd"

    count = state.regs.ecx
    assert not state.se.symbolic(count)
    count = state.se.any_int(count)

    ptr = state.regs.edi
    assert not state.se.symbolic(ptr)
    ptr = state.se.any_int(ptr)

    value = state.regs.eax
    assert not state.se.symbolic(value)
    value = state.se.any_int(value)
    assert value == 0x0

    state.memory.store(ptr, claripy.Reverse(claripy.BVV(0x0, 32 * count))) 
    state.regs.ecx = 0
    state.regs.edi += count * 4

    """
    for i in range(count):
        state.memory.store(ptr + (i * 4), claripy.Reverse(claripy.BVV(value, 32))) 
        state.regs.edi += 4
        state.regs.ecx -= 1
    """

# speed up rep
proj.hook(0x402f4e, rep_stosd, length=2)
proj.hook(0x4032D3, rep_stosd, length=2)
#proj.hook(0x403B3B, rep_stosd, length=2)

def debug_cmd(state):
    pdb.set_trace()

#proj.hook(0x4032FF, debug_cmd)

def fix_xor_key(state):
    state.se.add(state.regs.cl == 69)

proj.hook(0x4033CC, fix_xor_key)

# get max used addr from imports
import_max_addr = 0
for s in proj.loader.main_object.imports:
   import_max_addr = import_max_addr if import_max_addr > proj.loader.main_object.imports[s].addr else proj.loader.main_object.imports[s].addr

import_max_addr = 0x40AA9F # to be safe let's avoid conflicts...

# install api hooks
for api in api_hooks:

    addr = api_hooks[api]
    name = api.__name__

    ## ? This could've been done with hook_symbol
    if name in proj.loader.main_object.imports:

        addr = proj.loader.main_object.imports[name].addr

        # fix issue with indirect call
        # state.memory.store(rebased_addr, claripy.Reverse(claripy.BVV(addr, 32)))
        # print "API: " + str(api.__name__ + " @ " + hex(addr) + " [" + hex(rebased_addr) + "]")

    else:
        addr = import_max_addr
        import_max_addr = import_max_addr + 4
        symb = WinSymbol(owner=proj.loader.main_object, name=name, addr=0, is_import=True, is_export=False,
                         ordinal_number=None,
                         forwarder=None)
        reloc = proj.loader.main_object._make_reloc(addr=cle.AT.from_lva(addr,
                    proj.loader.main_object).to_rva(),
                    reloc_type=None, symbol=symb, resolvewith=None)

        if reloc is not None:
            proj.loader.main_object.imports[name] = reloc
            proj.loader.main_object.relocs.append(reloc)

    # install hook
    print "Hook API: " + str(api.__name__ + " @ " + hex(addr))
    proj.hook(addr, api(), replace=True)

    # fix call with RVA
    reloc_addr = cle.AT.from_lva(addr, proj.loader.main_object).to_rva()
    proj.hook(reloc_addr, api(), replace=True)

win32_models.proj = proj
win32_models.api_hooks = api_hooks

command = { 
            #1:  [0x40331A, 0x403C49], 
            2:  [0x40343D, 0x403C49], 
            3:  [0x403492, 0x403C49],
            4:  [0x4034EE, 0x403C49],
            5:  [0x40355F, 0x403C49],
            6:  [0x403588, 0x403C49],
            7:  [0x4035B1, 0x403C49],
            9:  [0x403602, 0x403C49],
            0xA:  [0x40383A, 0x403C49],
            0xB:  [0x40388D, 0x403C49],
            0xC:  [0x4038B8, 0x403C49],
            0xD:  [0x40393D, 0x403C49],
            0xE:  [0x403966, 0x403C49],
            0xF:  [0x4039AA, 0x403C49],
            0x10: [0x403A33, 0x403C49],
            0x40: [0x403480, 0x403C49],
           }

k = 0
avoided = []

addr_to_avoid = [
                    0x403149, # avoid repeating inner loop
                    0x403385,
                    0x403416,
                ]

start_command = None
end_command = None
if len(sys.argv) > 1:

    n_cmd = int(sys.argv[1])
    assert n_cmd in command

    start_command = command[n_cmd][0]
    end_command = command[n_cmd][1]

    for n in command:
        if n != n_cmd:
            addr_to_avoid.append(command[n][0])


# 0403398

# not taken 403375

loop_start = 0x403059
delayed = []
visited_loop_start = 0
discaded = []

def null_sub(state):
    pass

def move_to_avoided(p):
    global avoided
    global pg

    pg.active.remove(p)
    avoided.append(p)

def contains_label(label, data):

    for a in data.args:

        if type(a) is str and label in a:
            return True

        if hasattr(a, 'args') and contains_label(label, a):
            return True

    return False

def has_symbolic_input_guard(p):

    data = p.state.scratch.guard
    if data is None:
        return False

    labels = ['InternetReadFile_buffer', 'ReadFile_bytes_written']
    for l in labels:
        if contains_label(l, data): 
            return True 

    return False

def fix_loop_iterations(pg):

    K_LOOP_ITERATION = 7

    parents = dict()

    # collect children of same loop
    for p in pg.active:
        parent = p.history.parent.state
        assert parent is not None
        # get a strong reference to the state
        parent = parent._get_strongref()
        if parent in parents:
            parents[parent].append(p)
        else:
            parents[parent] = [p,]

    if len(parents) > 1: # ToDo
        print "Multiple parents in fix_loop_iterations()"
        pdb.set_trace() 

    parent = parents.keys()[0]
    children = parents[parent]
    forward = []
    backward = []
    guard_input = True
    for p in children:

        if p.ip.args[0] > parent.ip.args[0]:
            forward.append(p)
        elif parent.ip.args[0] - 60 <= p.ip.args[0]:
            backward.append(p)

        if not has_symbolic_input_guard(p):
            guard_input = False
            break

    forced_return = False

    if not guard_input:
        print "Children do not have all input guard"
        #pdb.set_trace()
        return

    if len(children) != 2 or not (len(backward) == 1 and len(forward) == 1):
        print "Unexpected number of children and/or directions"
        #pdb.set_trace()
        return

    if forced_return:
        return

    count = parent.rat.lookup('loop_' + hex(parent.ip.args[0]))
    if count is None:
        count = 0

    if count is None or count < K_LOOP_ITERATION:

        print "\nDiscarding path going forward"

        for p in forward:
            pg.active.remove(p)
        for p in backward:
            p.rat.add('loop_' + hex(parent.ip.args[0]), count + 1)

    else:

        print "\nDiscarding path going backward"

        for p in backward:
            pg.active.remove(p)
        for p in forward:
            p.rat.remove('loop_' + hex(parent.ip.args[0]))

threshold_ops = 65000
last_picked = None

def move_to_delayed(pg):

    global delayed
    global threshold_ops

    try:
        if len(pg.active) > 1:

            targets = {}
            for p in pg.active[:]:

                t = p.state.ip.args[0]
                if t in targets:
                    targets[t].append(p)
                else:
                    targets[t] = [p,]

            sorted_targets = sorted(targets.keys())
            selected = targets[sorted_targets[-1]][0]
            others = pg.active[:]
            others.remove(selected)
            delayed += others
            for o in others:
                pg.active.remove(o)

        if len(pg.active) == 1:
            if pg.active[0].length > threshold_ops:
                p = pg.active[0]
                print "\nThe current path has been executed many times. Delayed when at " + hex(p.state.ip.args[0])
                pg.active.remove(p)    
                delayed.append(p)

        if len(pg.active) == 0 and len(delayed) > 0:
            pg.active.append(delayed[0])
            delayed.remove(pg.active[0])
            print "\nPicked path from delayed " + hex(pg.active[0].state.ip.args[0]) + " length=" + str(pg.active[0].length)

            global last_picked
            last_picked = pg.active[0]

            if pg.active[0].length + 500 > threshold_ops:
                print "Increasing threshold"
                threshold_ops += 500

            return
    
    except Exception as e:
        pdb.set_trace()


hit_start = False

step = False
step_from_addr = None

while len(pg.active) > 0:

    if len(pg.active) != 1:
        pdb.set_trace()

    assert len(pg.active) == 1

    state = pg.active[0].state
    eip = hex(state.ip.args[0])

    """
    if 0x40342E == state.ip.args[0]:
        print "\n\nFound path to 0x40342E"
        pdb.set_trace()

    if loop_start == state.ip.args[0]:

        print "\nAt loop start..."

        visited_loop_start += 1
        if visited_loop_start > 2:
            print "\nDiscarding path at " + eip + " since it has already visited loop_start: " + str(visited_loop_start)
            pdb.set_trace()
            discarded.append(pg.active[0])
            pg.active = [delayed[0][1]]
            visited_loop_start = delayed[0][1]
            delayed = delayed[1:] 
            state = pg.active[0].state
            eip = hex(state.ip.args[0])
    """


    if eip == hex(0x40331A):
        #pdb.set_trace()
        pass

    if eip == hex(0x40337D) or eip == hex(0x403369) or eip == hex(0x403373) or eip == hex(0x403365) or eip == hex(0x403394):
        #print eip
        #pdb.set_trace()
        pass

    if eip == hex(0x403423):
        # flip flag
        #state.memory.store(state.regs.esp + 0x1c, claripy.Reverse(claripy.BVV(0x1, 32)))
        pass

    if eip == hex(end_command):
        print "End of Command"
        if hit_start:
            state.rat.dump('cmd_log_' + str(n_cmd) + '.txt')
            pdb.set_trace()
        if last_picked != pg.active[0]:
            delayed.append(pg.active.pop())
            pg.active.append(delayed.pop(0))
        last_picked = None

    # compute stack frame size: this is useful when checking correctness with IDA
    stack_size = hex(state.callstack.current_stack_pointer - state.regs.esp.args[0] + 4)

    main_loop_visits = state.rat.lookup('main_loop_visits')
    main_loop_visits = main_loop_visits if main_loop_visits is not None else 0
    print "[" + str(k+1) + "] Executing at: " + eip + " stack_size=" + str(stack_size) \
          + " avoided=" + str(len(avoided)) + " delayed=" + str(len(delayed)) \
          + " length=" + str(pg.active[0].length) + " main_loop_visits=" + str(main_loop_visits)

    pg.step(num_inst=1) #
    k += 1

    #if eip == hex(0x4030FC):
    #    proj.hook(0x4030FC, null_sub, length=6)

    if state.regs.ip.args[0] == step_from_addr:
        step = True

    if step:
        pdb.set_trace();

    for p in pg.active:

        if p.ip.args[0] == loop_start:
            main_loop_visits = p.rat.lookup('main_loop_visits')
            print "Path " + str(p) + " is at the beginning of the main loop"
            main_loop_visits = main_loop_visits + 1 if main_loop_visits is not None else 1
            p.rat.add('main_loop_visits', main_loop_visits)
            if main_loop_visits >= 4:
                pdb.set_trace()
                pg.active.remove(p)
                print "Path has been discarded since has reached main loop " + str(main_loop_visits) + " times"
                pass

    if len(pg.active) > 1:

        to_remove = []

        selected = None
        for p in pg.active:        
            if p.state.ip.args[0] == start_command:
                print "\nReached start command..."
                #pdb.set_trace()
                hit_start = True
                if n_cmd == 4:
                    state.memory.store(arg_addr + 0x2804, claripy.Reverse(claripy.BVV(0x1, 32)))
                    #state.memory.store(arg_addr + 0xcac, claripy.Reverse(claripy.BVV(0x1, 32)))
                selected = p

        if selected is not None:
            print "One path selected, discarding other active or delayed states..."
            for p in pg.active[:]:
                if p != selected:
                    pg.active.remove(p)
            for p in delayed[:]:
                delayed.remove(p)

        for p in pg.active:

            if p.state.ip.args[0] in addr_to_avoid:
                print "\nDiscarding path at " + hex(p.state.ip.args[0])
                to_remove.append(p)

                #if 0x403423 == p.state.ip.args[0]:
                #    addr_to_avoid.remove(0x403423)
                #    addr_to_avoid.append(0x40331A)

        for p in to_remove:
            pg.active.remove(p)
            avoided.append(p)

        if len(pg.active) > 1:
            fix_loop_iterations(pg)

        #pdb.set_trace()

    move_to_delayed(pg)

pdb.set_trace()