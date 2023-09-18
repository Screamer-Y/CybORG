from CybORG import CybORG
import warnings
from typing import Any, Union

import gym
from gym.utils import seeding

from CybORG.Shared import Observation, Results, CybORGLogger
from CybORG.Shared.Enums import DecoyType
from CybORG.Shared.EnvironmentController import EnvironmentController
from CybORG.Shared.Scenarios.ScenarioGenerator import ScenarioGenerator
from CybORG.Simulator.Actions import DiscoverNetworkServices, DiscoverRemoteSystems, ExploitRemoteService, \
    InvalidAction, \
    Sleep, PrivilegeEscalate, Impact, Remove, Restore, SeizeControl, RetakeControl, RemoveOtherSessions, FloodBandwidth
from CybORG.Simulator.Actions.ConcreteActions.ActivateTrojan import ActivateTrojan
from CybORG.Simulator.Actions.ConcreteActions.ControlTraffic import BlockTraffic, AllowTraffic
from CybORG.Simulator.Actions.ConcreteActions.ExploitActions.ExploitAction import ExploitAction
from CybORG.Simulator.Scenarios import DroneSwarmScenarioGenerator
from CybORG.Tests.utils import CustomGenerator

import yaml
from typing import Dict, List
from CybORG.Simulator.AbstractVulnerability import AbstractVulnerability

class CybORGExtension(CybORG):
    """
    add hostname-abstract vulnerability mapping
    """
    def __init__(self,
                 scenario_generator: ScenarioGenerator, environment: str="sim", env_config=None, agents: dict=None, seed: Union[int,CustomGenerator]=None,
                 host_absvul_map: Dict[str, List[AbstractVulnerability]] = None):
        """Instantiates the Extension class.

        Parameters
        ----------
        host_absvul_map : Dict[str, List[AbstractVulnerability]], optional
            A dict define abstract vulerabilities in host.
        """
        super().__init__(scenario_generator=scenario_generator, environment=environment, env_config=env_config, agents=agents, seed=seed)
        self.host_absvul_map = host_absvul_map
        for host,boolean in self.environment_controller.agent_interfaces['Red'].action_space.hostname.items():
            if boolean:
                self.environment_controller.state.discovered_sequence.append(host)        

    def init_update_attacker_action_history(self, host_absvul_map, obs):
        obs_data = obs.data
        for hostname,_ in self.environment_controller.state.hosts.items():
            obs_data['action_history'][hostname] = {vul_id:{'success':False,'failure':False} for _,vul_dict in host_absvul_map.items() for vul_id,_ in vul_dict.items()}
        for _, vul_dict in host_absvul_map.items():
            for vul_id, vul in vul_dict.items():
                for ind, history in vul.history.items(): 
                    if history['host'] == 'Defender_RollBack':
                        continue
                    if history['success']:
                        obs_data['action_history'][history['host']][vul_id]['success'] = True
                    else:
                        obs_data['action_history'][history['host']][vul_id]['failure'] = True

    def update_host_absvul_action_space(self):
        self.environment_controller.agent_interfaces['Red'].action_space.absvul = {}
        for _, vul_dict in self.host_absvul_map.items():
            for _, vul in vul_dict.items():
                self.environment_controller.agent_interfaces['Red'].action_space.absvul[vul] = True

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
                av = AbstractVulnerability(v_id, v_type, hostname, self.environment_controller, v_value['target_host_id'], v_outcome, v_value['description'], None, v_value['bonus'], v_value['cost'])
                host_absvul_map[hostname][v_id] = av
        self.host_absvul_map = host_absvul_map
        self.environment_controller.state.host_absvul_map = self.host_absvul_map
        self.update_host_absvul_action_space()
        self.init_update_attacker_action_history(self.host_absvul_map, self.environment_controller.observation['Red'])

    @property
    def get_host_absvul_map(self):
        return self.host_absvul_map

    def reset(self, agent: str = None, seed: int = None):
        results = super().reset(agent, seed)
        self.environment_controller.state.host_absvul_map = self.host_absvul_map
        self.update_host_absvul_action_space()
        return results

# class CybORGExtension(ABC):
#     """
#     add hostname-abstract vulnerability mapping
#     """

#     def __init__(self,
#                  cyborg: CybORG,
#                  host_absvul_map: Dict[str, List[AbstractVulnerability]] = None):
#         """Instantiates the Extension class.

#         Parameters
#         ----------
#         cyborg : CybORG
#             CybORG object that used.
#         host_absvul_map : Dict[str, List[AbstractVulnerability]], optional
#             A dict define abstract vulerabilities in host.
#         """
#         self.cyborg = cyborg
#         self.host_absvul_map = host_absvul_map
#         for host,boolean in self.cyborg.environment_controller.agent_interfaces['Red'].action_space.hostname.items():
#             if boolean:
#                 self.cyborg.environment_controller.state.discovered_sequence.append(host)

#     def update_host_absvul_action_space(self):
#         self.cyborg.environment_controller.agent_interfaces['Red'].action_space.absvul = {}
#         for _, vul_dict in self.host_absvul_map.items():
#             for _, vul in vul_dict.items():
#                 self.cyborg.environment_controller.agent_interfaces['Red'].action_space.absvul[vul] = True

#     def load_host_absvul_map_from_yaml(self, path):
#         def map_type_outcome(input_str):
#             if input_str=='LOCAL':
#                 return AbstractVulnerability.VulnerabilityType.LOCAL
#             elif input_str=='REMOTE':
#                 return AbstractVulnerability.VulnerabilityType.REMOTE
#             elif input_str=='IP_DISCOVERED':
#                 return AbstractVulnerability.Outcome.IP_DISCOVERED
#             elif input_str=='SERVICE_EXPLOITED':
#                 return AbstractVulnerability.Outcome.SERVICE_EXPLOITED
#             else:
#                 raise ValueError("Invalid Vulnerability Type or Outcome name.")
#         with open(path) as fIn:
#             host_absvul_dict = yaml.load(fIn, Loader=yaml.FullLoader)
#         host_absvul_map = {}
#         for hostname,vulnerability in host_absvul_dict.items():
#             host_absvul_map[hostname] = {}
#             for v_id,v_value in vulnerability.items():
#                 v_type = map_type_outcome(v_value['vulnerability_type'])
#                 v_outcome = map_type_outcome(v_value['outcome'])
#                 av = AbstractVulnerability(v_id, v_type, hostname, self.cyborg.environment_controller, v_value['target_host_id'], v_outcome, v_value['description'], None, v_value['bonus'], v_value['cost'])
#                 host_absvul_map[hostname][v_id] = av
#         self.host_absvul_map = host_absvul_map
#         self.cyborg.environment_controller.state.host_absvul_map = self.host_absvul_map
#         self.update_host_absvul_action_space()

#     @property
#     def get_host_absvul_map(self):
#         return self.host_absvul_map

#     def step(self):
#         pass

#     def reset(self, agent: str = None, seed: int = None):
#         if seed is not None:
#             self.cyborg.np_random, seed = seeding.np_random(seed)
#         results = self.cyborg.environment_controller.reset(agent=agent, np_random=self.cyborg.np_random)
#         self.cyborg.environment_controller.state.host_absvul_map = self.host_absvul_map
#         self.update_host_absvul_action_space()
#         return results
