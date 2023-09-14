

from CybORG.Shared import Observation
from .Monitor import Monitor
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Actions.ConcreteActions.RestoreFromBackup import RestoreFromBackup
from CybORG.Simulator.Session import VelociraptorServer
from CybORG.Simulator.Actions.AbstractActions import Monitor
from CybORG.Simulator.Host import Status

REIMAGE_DURATION = 5

class Restore(Action):
    def __init__(self, session: int, agent: str, hostname: str):
        super().__init__()
        self.agent = agent
        self.session = session
        self.hostname = hostname

    def record_restore(self, success, state):
        if self.hostname not in state.restore_history:
            state.restore_history[self.hostname] = {'success':False,'failure':False}
        if success:
            state.restore_history[self.hostname]['success'] = True
        else:
            state.restore_history[self.hostname]['failure'] = True

    def execute(self, state) -> Observation:
        # check whether the host is running or reimaging
        if not state.hosts[self.hostname].status == Status.RUNNING:
            obs = Observation(success=False)
            self.record_restore(False, state)
            return obs
        # check if session exists
        if self.session not in state.sessions[self.agent]:
            self.record_restore(False, state)
            return Observation(False)
        parent_session: VelociraptorServer = state.sessions[self.agent][self.session]
        # find relevant session on the chosen host
        sessions = [s for s in state.sessions[self.agent].values() if s.hostname == self.hostname]
        if len(sessions) > 0:
            session = state.np_random.choice(sessions)
            obs = Observation(True)
            # restore host
            action = RestoreFromBackup(session=self.session, agent=self.agent, target_session=session.ident)
            action.execute(state)
            state.hosts[self.hostname].status = Status.REIMAGING
            state.hosts[self.hostname].reimage_step = REIMAGE_DURATION
            self.record_restore(True, state)
            return obs
        else:
            self.record_restore(False, state)
            return Observation(False)

    @property
    def cost(self):
        return -1

    def __str__(self):
        return f"{self.__class__.__name__} {self.hostname}"
