from CybORG.Shared import Observation
from CybORG.Simulator.Actions import Action
from CybORG.Simulator.Session import VelociraptorServer
from CybORG.Simulator.State import State

SCAN_RATE = 0.1
FP_RATE = 0.1

class Scan(Action):
    def __init__(self, session: int, agent: str):
        super().__init__()
        self.agent = agent
        self.session = session

    def execute(self, state: State) -> Observation:
        obs = Observation(True)
        state.last_scan = []
        for _,vulnerability_dict in state.host_absvul_map.items():
            for vul_id,vulnerability in vulnerability_dict.items():
                # if vul.exploited, have a rate to return a obs
                if vulnerability.exploited and state.np_random.random()>SCAN_RATE:
                    hostname = vulnerability.hostname
                    target_ip = [interface.ip_address for interface in state.hosts[hostname].interfaces]
                    target_subnet = [interface.subnet for interface in state.hosts[hostname].interfaces]
                    for i in range(len(target_ip)):
                        obs.add_interface_info(hostid=str(target_ip[i]), subnet=target_subnet[i], ip_address=target_ip[i])
                    state.last_scan.append(hostname)
                # if not exploited, have a rate to return a obs as a false positive
                if not vulnerability.exploited and state.np_random.random()<FP_RATE:
                    hostname = vulnerability.hostname
                    target_ip = [interface.ip_address for interface in state.hosts[hostname].interfaces]
                    target_subnet = [interface.subnet for interface in state.hosts[hostname].interfaces]
                    for i in range(len(target_ip)):
                        obs.add_interface_info(hostid=str(target_ip[i]), subnet=target_subnet[i], ip_address=target_ip[i])
                    state.last_scan.append(hostname)
        return obs


    def __str__(self):
        return f"{self.__class__.__name__}"
