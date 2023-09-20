import random
from datetime import datetime
import numpy as np

from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper
from CybORG.Shared.Enums import OperatingSystemType, SessionType, ProcessName, Path, ProcessType, ProcessVersion, \
    AppProtocol, FileType, ProcessState, Vulnerability, Vendor, PasswordHashType, BuiltInGroups, \
    OperatingSystemDistribution, OperatingSystemVersion, OperatingSystemKernelVersion, Architecture, \
    OperatingSystemPatch, FileVersion


class DictFlatWrapper(BaseWrapper):
    def __init__(self, env: BaseWrapper = None):
        super().__init__(env)
        self.n_host = None

    def transform_value(self, key_name, value):
        if key_name == 'running_status' or key_name == 'suspicous':
            return value
        if key_name == 'discovered_sequence':
            if value=='Unknown':
                return 0
            else:
                return value+1

    def transform_action_history_value(self, action_history_dict, host_state_list):
        for vul_id, history_dict in action_history_dict.items():
            for key, value in history_dict.items():
                if value:
                    host_state_list.append(1)
                else:
                    host_state_list.append(0)

    def observation_change(self, agent, obs: dict) -> list:
        if 'message' in obs:
            obs.pop('message')
        if 'success' in obs:
            obs.pop('success')
        numeric_obs = obs
        flat_obs = {}

        # extract the host name
        temp_list = list(numeric_obs.keys())
        hostname_list = list(numeric_obs[temp_list[0]].keys())
        self.n_host = len(hostname_list)
        count = 0
        # form the obs matrix
        for hostname in hostname_list:
            host_state_list = []
            for key_name, item in numeric_obs.items():
                if key_name=='action_history':
                    self.transform_action_history_value(item[hostname],host_state_list)
                else:
                    host_state_list.append(self.transform_value(key_name, item[hostname]))
            flat_obs[f"host{count}"] = np.array(host_state_list)
            count+=1

        return flat_obs

    def get_attr(self, attribute: str):
        return self.env.get_attr(attribute)

    def get_observation(self, agent: str):
        obs = self.get_attr('get_observation')(agent)
        return self.observation_change(agent, obs)
