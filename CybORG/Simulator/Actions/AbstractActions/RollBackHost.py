from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Session import VelociraptorServer
from CybORG.Simulator.State import State
from ipaddress import IPv4Address
from CybORG.Shared import AgentInterface
from CybORG.Simulator.Actions.AbstractActions import Remove, EraseIP, RollBackVulnerability
from CybORG.Simulator.AbstractVulnerability import AbstractVulnerability
from random import shuffle
from CybORG.Simulator.Host import Status



class RollBackHost(Action):
    def __init__(self, session: int, agent: str, hostname:str):
        super().__init__()
        self.agent = agent
        self.session = session
        self.hostname = hostname

    def record_rollback(self, obs, vulnerability: AbstractVulnerability):
        # Record the exploitation
        if obs.success:
            vulnerability.history[len(vulnerability.history)+1] = {'host':'Defender_RollBack', 'success':True}
        else:
            vulnerability.history[len(vulnerability.history)+1] = {'host':'Defender_RollBack', 'success':False}

    def execute(self, state: State) -> Observation:
        # Randomly select a vulnerability in the host and roll it back.
        # TODO: get a dummy vulnerability in the host, if failed, use the vul to record failure.
        if self.hostname in state.host_absvul_map:
            vulnerability_list = list(state.host_absvul_map[self.hostname].values())
            if len(vulnerability_list)>0:
                dummy_vulnerability = vulnerability_list[0]
            else:
                dummy_vulnerability = AbstractVulnerability()
        else:
            dummy_vulnerability = AbstractVulnerability()
        # check whether the host is running or reimaging
        if not state.hosts[self.hostname].status == Status.RUNNING:
            obs = Observation(success=False)
            self.record_rollback(obs, dummy_vulnerability)
            return obs
        host_absvul_map = state.host_absvul_map
        if self.hostname not in host_absvul_map:
            obs = Observation(False)
            self.record_rollback(obs, dummy_vulnerability)
            return obs
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
            obs = Observation(False)
            self.record_rollback(obs, dummy_vulnerability)
            return obs
        sub_action = RollBackVulnerability(self.session, self.agent, selected_vulnerability)
        if selected_vulnerability.outcome == AbstractVulnerability.Outcome.IP_DISCOVERED:
            state.discovered_sequence.pop(state.discovered_sequence.index(self.hostname))
        obs = sub_action.execute(state)
        self.record_rollback(obs, selected_vulnerability)
        return obs

    def __str__(self):
        return f"{self.__class__.__name__} {self.absvul.vulnerability_id}"
