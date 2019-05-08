from symba.triggers import TriggerSource

from angr import ExplorationTechnique


class TriggerSeer(ExplorationTechnique):
    """ A pretty simple ExplorationTechnique
    to model a termination condition for the
    trigger analysis: if a trigger source is
    not referenced in a constraint for more
    than a given threshold number of steps,
    the exploration is completed.
    The rationale behind so is that, once
    a value is produced from a source, the
    relative triggerconditions
    will be computed shortly thereafter.
    """

    def __init__(self, trigger: str, threshold=10):
        super(TriggerSeer, self).__init__()
        self.trigger = trigger
        self._threshold = threshold
        self._count = 0
        self._registry = set()
        self._not_injected = True

    def _recently_constrained(self, state):
        if not self.trigger in state.globals:
            # If trigger has not been injected, yet,
            # return true, so that exploration continues.
            # but as soon as one state gets its injection,
            # we expect that at least 1 state among the actives
            # contains a new constraint, to continue exploration.
            return self._not_injected
        self._not_injected = True

        collected_constraints = set()

        for bv in state.globals[self.trigger].values():
            collected_constraints |= set(
                (constraint for constraint in state.solver.constraints
                 if not bv.variables.isdisjoint(constraint.variables)))

        # Update registry with recent constraints
        if collected_constraints - self._registry:
            self._registry |= collected_constraints
            return True

        return False

    def step(self, simgr, stash='active', **kwargs):
        if not any(
                self._recently_constrained(state)
                for state in simgr.stashes[stash]):
            self._count += 1
        else:
            self._count = 0

        return simgr.step(stash=stash, **kwargs)

    def complete(self, simgr):
        return self._count >= self._threshold