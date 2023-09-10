from CybORG import CybORG
from abc import ABC
import yaml
from typing import Dict, List
from CybORG.Simulator.AbstractVulnerability import AbstractVulnerability


class CybORGExtension(ABC):
    """
    add hostname-abstract vulnerability mapping
    """

    def __init__(self,
                 cyborg: CybORG,
                 host_absvul_map: Dict[str, List[AbstractVulnerability]] = None):
        """Instantiates the Extension class.

        Parameters
        ----------
        cyborg : CybORG
            CybORG object that used.
        host_absvul_map : Dict[str, List[AbstractVulnerability]], optional
            A dict define abstract vulerabilities in host.
        """
        self.cyborg = cyborg
        self.host_absvul_map = host_absvul_map
        for host,boolean in self.cyborg.environment_controller.agent_interfaces['Red'].action_space.hostname.items():
            if boolean:
                self.cyborg.environment_controller.state.discovered_sequence.append(host)

    def update_host_absvul_action_space(self):
        self.cyborg.environment_controller.agent_interfaces['Red'].action_space.absvul = {}
        for _, vul_dict in self.host_absvul_map.items():
            for _, vul in vul_dict.items():
                self.cyborg.environment_controller.agent_interfaces['Red'].action_space.absvul[vul] = True

    def load_host_absvul_map_from_yaml(self, path):
        def map_type_outcome(input_str):
            if input_str=='LOCAL':
                return AbstractVulnerability.VulnerabilityType.LOCAL
            elif input_str=='REMOTE':
                return AbstractVulnerability.VulnerabilityType.REMOTE
            elif input_str=='IP_DISCOVERED':
                return AbstractVulnerability.Outcome.IP_DISCOVERED
            elif input_str=='SERVICE_EXPLOITED':
                return AbstractVulnerability.Outcome.SERVICE_EXPLOITED
            else:
                raise ValueError("Invalid Vulnerability Type or Outcome name.")
        with open(path) as fIn:
            host_absvul_dict = yaml.load(fIn, Loader=yaml.FullLoader)
        host_absvul_map = {}
        for hostname,vulnerability in host_absvul_dict.items():
            host_absvul_map[hostname] = {}
            for v_id,v_value in vulnerability.items():
                v_type = map_type_outcome(v_value['vulnerability_type'])
                v_outcome = map_type_outcome(v_value['outcome'])
                av = AbstractVulnerability(v_id, v_type, hostname, self.cyborg.environment_controller, v_value['target_host_id'], v_outcome, v_value['description'])
                host_absvul_map[hostname][v_id] = av
        self.host_absvul_map = host_absvul_map
        self.cyborg.environment_controller.state.host_absvul_map = self.host_absvul_map
        self.update_host_absvul_action_space()

    @property
    def get_host_absvul_map(self):
        return self.host_absvul_map

    def step(self):
        pass
