from ipaddress import IPv4Network

from CybORG.Shared import Observation
from CybORG.Simulator.Actions.Action import RemoteAction
from CybORG.Simulator.Actions.ConcreteActions.LocalAction import LocalAction
from CybORG.Simulator.Actions.Action import lo_subnet, lo
from CybORG.Simulator.State import State
from CybORG.ReproductionExtension.Simulator.AbstractVulnerability import AbstractVulnerability
from CybORG.ReproductionExtension.Simulator.StateExtension import StateExtension


class IPDiscovered(RemoteAction):
    """
    Concrete action that reveal ips by an AbstractVulnerability.
    """
    def __init__(self, session: int, agent: str, hostname:str, absvul: AbstractVulnerability):
        super().__init__(session, agent)
        self.hostname = hostname
        self.absvul = absvul

    def execute(self, state: StateExtension) -> Observation:
        """
        Executes a pingsweep in the simulator.
        """
        obs = Observation()

        # # Check the session running the code exists and is active.
        # if self.session not in state.sessions[self.agent]:
        #     obs.set_success(False)
        #     return obs
        # from_host = state.hosts[state.sessions[self.agent][self.session].hostname]
        # session = state.sessions[self.agent][self.session]
        # if not session.active:
        #     obs.set_success(False)
        #     return obs
        # Collect the ip addresses in absvul
        if isinstance(self.absvul.outcome, AbstractVulnerability.Outcome.IP_DISCOVERED):
            for target_host in self.absvul.target_host_id:
                target_ip = [interface.ip_address for interface in state.hosts[target_host].interfaces]
                target_subnet = [interface.subnet for interface in state.hosts[target_host].interfaces]
                obs.set_success(True)
                for i in range(len(target_ip)):
                    obs.add_interface_info(hostid=str(target_ip), subnet=target_subnet[i], ip_address=target_ip[i])
        # Record exploit
        self.absvul.history[len(self.absvul.history)+1] = {'host':self.hostname, 'success':True}
        return obs
