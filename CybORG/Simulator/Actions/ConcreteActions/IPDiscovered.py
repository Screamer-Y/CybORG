from ipaddress import IPv4Network

from CybORG.Shared import Observation
from CybORG.Simulator.Actions.Action import RemoteAction
from CybORG.Simulator.Actions.ConcreteActions.LocalAction import LocalAction
from CybORG.Simulator.Actions.Action import lo_subnet, lo
from CybORG.Simulator.State import State
from CybORG.Simulator.AbstractVulnerability import AbstractVulnerability
from CybORG.Simulator.StateExtension import StateExtension


class IPDiscovered(RemoteAction):
    """
    Concrete action that reveal ips by an AbstractVulnerability.
    """
    def __init__(self, session: int, agent: str, hostname:str, target_host_id: str):
        super().__init__(session, agent)
        self.hostname = hostname
        self.target_host_id = target_host_id

    def execute(self, state: StateExtension) -> Observation:
        """
        Executes a pingsweep in the simulator.
        """
        obs = Observation()

        # Check the session running the code exists and is active.
        if self.session not in state.sessions[self.agent]:
            obs.set_success(False)
            return obs
        from_host = state.hosts[state.sessions[self.agent][self.session].hostname]
        session = state.sessions[self.agent][self.session]
        if not session.active:
            obs.set_success(False)
            return obs
        # Collect the ip addresses in target_host_id
        target_ip = [interface.ip_address for interface in state.hosts[self.target_host_id].interfaces]
        target_subnet = [interface.subnet for interface in state.hosts[self.target_host_id].interfaces]
        obs.set_success(True)
        for i in range(len(target_ip)):
            obs.add_interface_info(hostid=str(target_ip[i]), subnet=target_subnet[i], ip_address=target_ip[i])
        # Record exploit
        # self.absvul.history[len(self.absvul.history)+1] = {'host':self.hostname, 'success':True}
        return obs
