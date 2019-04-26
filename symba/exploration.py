from angr import ExplorationTechnique


class TriggerSeer(ExplorationTechnique):
    """This is just a try to implement
    an exploration technique. Not stable.
    WONTFIX
    """

    def __init__(self, count_threshold=10, count_name='counter'):
        super(TriggerSeer, self).__init__()
        self.count_stash = count_name
        self.count_threshold = count_threshold

    def setup(self, simgr):
        if self.count_stash not in simgr.stashes:
            simgr.stashes[self.count_stash] = []

    def step(self, simgr, stash='active', **kwargs):
        simgr.stashes[self.count_stash].append("JUNK")
        simgr = simgr.step(stash=stash, **kwargs)
        return simgr

    def complete(self, simgr):
        return len(simgr.stashes[self.count_stash]) >= self.count_threshold
