import angr

class RatLogger(angr.state_plugins.plugin.SimStatePlugin):

    def __init__(self, data=[]):
        self.state = None
        self.data = data

    def set_state(self, state):
        self.state = state

    def add(self, name, o):

        for k in range(len(self.data)):
            d = self.data[k]
            if d[0] == name: # replace old with new
                self.data[k] = [name, o]
                return

        self.data.append([name, o])

    def add_unique(self, name, o):
        self.data.append([name + " #" + str(len(self.data)), o])

    def rename(self, old_name, new_name):
        for k in range(len(self.data)):
            d = self.data[k]
            if d[0] == old_name: # replace old with new
                self.data[k] = [new_name, d[1]]
                return

    def remove(self, name):
        for d in self.data[:]:
            if d[0] == name:
                self.data.remove(d)

    def lookup(self, name):
        for d in self.data:
            if d[0] == name:
                return d[1]
        return None

    def __getstate__(self):
        return self.state

    def copy(self):
        r = RatLogger(self.data[:])
        return r

    def init_state(self):
        pass

    def print_last(self):
        e = self.data[-1]
        e[1].state = self.state
        print e[0]# + " " + str(e[1])
        e[1].state = None

    def dump(self, f):
        with open(f, "w") as o:
            try:
                count = 0
                for x in self.data:
                    if hasattr(x[1], 'state'):
                        x[1].state = self.state
                    o.write(str(x[1]) + "\n")
                    print "Dumped: " + str(count+1) + " / " + str(len(self.data))
                    count += 1
                    if hasattr(x[1], 'state'):
                        x[1].state = None
            except:
                import pdb
                pdb.set_trace()