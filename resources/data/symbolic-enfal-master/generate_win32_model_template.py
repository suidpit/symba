import sys

type_to_simtype = {
	'HINTERNET' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'LPCTSTR' : 'self.ty_ptr(simuvex.s_type.SimTypeString())',
	'INTERNET_PORT' : 'simuvex.s_type.SimTypeShort()',
	'DWORD' : 'simuvex.s_type.SimTypeInt()',
	'DWORD_PTR' : 'self.ty_ptr(simuvex.s_type.SimTypeInt())',
	'LPVOID' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'BOOL' : 'simuvex.s_type.SimTypeInt()',
	'LPINTERNET_BUFFERS' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'LPSECURITY_ATTRIBUTES' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'HANDLE' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'LPWIN32_FIND_DATA' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'UINT': 'simuvex.s_type.SimTypeInt()',
	'LPCSTR': 'self.ty_ptr(simuvex.s_type.SimTypeString())',
	'LPTSTR' : 'self.ty_ptr(simuvex.s_type.SimTypeString())',
	'LPSECURITY_ATTRIBUTES': 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'LPSTARTUPINFO' :  'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'LPPROCESS_INFORMATION' :  'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'HKEY' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'REGSAM' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'PHKEY' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'LONG' : 'simuvex.s_type.SimTypeLong()',
	'BYTE' : 'simuvex.s_type.SimTypeChar()',
	'LPTHREAD_START_ROUTINE' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'SIZE_T': 'simuvex.s_type.SimTypeLength()',
	'LPDWORD': 'self.ty_ptr(simuvex.s_type.SimTypeInt())',
	'LPCVOID' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'LPOVERLAPPED' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'LPFILETIME' : 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
	'* FILETIME': 'self.ty_ptr(simuvex.s_type.SimTypeTop(self.state.arch))',
}

return_type = None
name = None
args = []

signature = ""

for line in sys.stdin:

	line = line.rstrip('\n')
	if len(line) <= 0:
		continue

	if '(' in line:
		signature += line + "\n"
		line = [ a for a in line.split(' ') if len(a) > 0 ]
		if len(line) == 2:
			return_type = line[0]
			name = line[1].split('(')[0]
		elif len(line) == 3:
			return_type = line[0]
			name = line[2].split('(')[0]
		else:
			assert False

	elif ');' in line:
		signature += line + "\n"
		break

	elif ',' in line or name is not None:
		signature += line + "\n"
		line = line.replace('const', '')
		star = False
		if '*' in line:
			star = True
			line = line.replace('*', '')

		line = [ a for a in line.split(' ') if len(a) > 0 ]

		t = line[1]
		if star:
			t = '* ' + t
		n = line[2].replace(',', '').replace('*', '')
		args.append([t, n])

print "Parsed: "
print return_type
print name
print args
print
print signature

if return_type is None or return_type == 'VOID':
	return_type = 'DWORD'

print
print "Template:\n"

print "class " + name + "(simuvex.SimProcedure):"
print
print "    def execute(self, state, successors=None, arguments=None, ret_to=None):"
print "        super(" + name + ", self).execute(state, successors, arguments, ret_to)"
print "        state.regs.esp += 4 * " + str(len(args))
print

sys.stdout.write("    def run(self, ")
for k in range(len(args)):
	a = args[k]
	sys.stdout.write(a[1] + (", " if k < len(args) - 1 else ""))
print "):"
print

sys.stdout.write("        self.argument_types = {\n")
for k in range(len(args)):
	a = args[k]
	t = type_to_simtype[a[0]]
	sys.stdout.write("            " + str(k) + ": " + t + ",\n")
sys.stdout.write("            }\n")

print

t = type_to_simtype[return_type]
print "        self.return_type = " + t
print
print "        ret_expr = ?"

sys.stdout.write("        print \"" + name + ": \"")
for k in range(len(args)):
	a = args[k]
	sys.stdout.write(' + str(' + a[1] + ') + " "')
sys.stdout.write(' + "=> "' + ' + str(ret_expr)' + "\n")
        
print "        return ret_expr"