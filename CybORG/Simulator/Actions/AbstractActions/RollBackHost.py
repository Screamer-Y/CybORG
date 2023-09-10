from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Session import VelociraptorServer
from CybORG.Simulator.State import State
from ipaddress import IPv4Address
from CybORG.Shared import AgentInterface
from CybORG.Simulator.Actions.AbstractActions import Remove, EraseIP, RollBackVulnerability
from CybORG.Simulator.AbstractVulnerability import AbstractVulnerability
from random import shuffle



class RollBackHost(Action):
    def __init__(self, session: int, agent: str, hostname:str):
        super().__init__()
        self.agent = agent
        self.session = session
        self.hostname = hostname

    def execute(self, state: State) -> Observation:
        # Randomly select a vulnerability in the host and roll it back.
        # TODO: record history
        host_absvul_map = state.host_absvul_map
        if self.hostname not in host_absvul_map:
            return Observation(False)
        vul_dict = host_absvul_map[self.hostname]
        keys = list(vul_dict.keys())
        shuffle(keys)
        flag = True
        for k in keys:
            selected_vulnerability: AbstractVulnerability = vul_dict[k]
            if selected_vulnerability.exploited:
                flag = False
                break
        if flag:
            return Observation(False)
        sub_action = RollBackVulnerability(self.session, self.agent, selected_vulnerability)
        obs = sub_action.execute(state)
        return obs

    def __str__(self):
        return f"{self.__class__.__name__} {self.absvul.vulnerability_id}"
