from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Session import VelociraptorServer
from CybORG.Simulator.State import State
from ipaddress import IPv4Address
from CybORG.Shared import AgentInterface


class EraseIP(Action):
    def __init__(self, session: int, agent: str, hostname: str, agent_interface:AgentInterface):
        super().__init__()
        self.agent = agent
        self.session = session
        self.hostname = hostname
        self.agent_interface = agent_interface

    def execute(self, state: State) -> Observation:

        parent_session: VelociraptorServer = state.sessions[self.agent][self.session]
        # find relevant session on the chosen host
        sessions = [s for s in state.sessions[self.agent].values() if s.hostname == self.hostname]
        if len(sessions) > 0:
            session = state.np_random.choice(sessions)
            obs = Observation(True)
            # erase ip
            # TODO: think of the observation
            swapped_dict = {v:k for k,v in state.ip_addresses.items()}
            ip_address = swapped_dict[self.hostname]
            self.agent_interface.action_space.ip_address[ip_address] = False
            return obs
        else:
            return Observation(False)

    def __str__(self):
        return f"{self.__class__.__name__} {self.hostname}"
