import inspect

import numpy as np
from gym import spaces, Env
from typing import Union, List, Optional, Tuple

from prettytable import PrettyTable

from CybORG.Agents.SimpleAgents.BaseAgent import BaseAgent
from CybORG.Agents.Wrappers.BaseWrapper import BaseWrapper

class OpenAIGymWrapper(Env, BaseWrapper):
    def __init__(self, env: BaseWrapper, agent_name: str):
        super().__init__(env)
        self.agent_name = agent_name
        self.action_signature = {}
        if isinstance(self.get_action_space(self.agent_name), list):
            self.action_space = spaces.MultiDiscrete(self.get_action_space(self.agent_name))
        else:
            assert isinstance(self.get_action_space(self.agent_name), int)
            self.action_space = spaces.Discrete(self.get_action_space(self.agent_name))
        # modification
        # box_len = len(self.observation_change(agent_name, self.env.reset(self.agent_name).observation))
        # self.observation_space = spaces.Box(-1.0, 3.0, shape=(box_len,), dtype=np.float32)
        obs = self.observation_change(agent_name, self.env.reset(agent_name).observation)
        n_host = len(obs)
        if self.agent_name == 'Red':
            host_state_list = [3, n_host+1]
        elif self.agent_name == 'Blue':
            host_state_list = [3, 2]
        host_state_list.extend([2]*(len(list(obs.values())[0])-2))
        self.observation_space = spaces.Dict({f"host{i}":spaces.MultiDiscrete(host_state_list) for i in range(n_host)})
        self.reward_range = (float('-inf'), float('inf'))
        self.metadata = {}
        self.action = None
        self.render_mode = 'human'

    def step(self, action: Union[int, List[int]] = None) -> Tuple[object, float, bool, dict]:
        if action is not None:
            action = self.possible_actions[action]
        self.action = action
        result = self.env.step(self.agent_name, action)
        
        result.observation = self.observation_change(self.agent_name, result.observation)
        result.action_space = self.action_space_change(result.action_space)
        info = vars(result)
        return result.observation, result.reward, result.done, info

    @property
    def np_random(self):
        return self.env.get_attr('np_random')

    def reset(self, *, seed: Optional[int] = None, return_info: bool = False, options: Optional[dict] = None):
        result = self.env.reset(self.agent_name, seed)
        result.action_space = self.action_space_change(result.action_space)
        result.observation = self.observation_change(self.agent_name, result.observation)
        if return_info:
            # modification
            return result.observation, {}
            # return np.array(result.observation, dtype=np.float32), {}
        else:
            return result.observation
            # return np.array(result.observation, dtype=np.float32)

    def render(self, mode='human'):
        return self.env.render(mode)

    def get_attr(self,attribute:str):
        return self.env.get_attr(attribute)

    def get_observation(self, agent: str):
        observation = self.env.get_observation(agent)
        observation = self.observation_change(self.agent_name, observation)
        return np.array(observation, dtype=np.float32)

    def get_agent_state(self,agent:str):
        return self.get_attr('get_agent_state')(agent)

    def get_action_space(self,agent):
        return self.action_space_change(self.env.get_action_space(agent))

    def get_last_action(self,agent):
        return self.get_attr('get_last_action')(agent)

    def get_ip_map(self):
        return self.get_attr('get_ip_map')()

    def get_rewards(self):
        return self.get_attr('get_rewards')()

    def action_space_change(self, action_space: dict) -> int:
        assert type(action_space) is dict, \
            f"Wrapper required a dictionary action space. " \
            f"Please check that the wrappers below return the action space as a dict "
        possible_actions = []
        temp = {}
        params = ['action']
        # for action in action_space['action']:
        for i, action in enumerate(action_space['action']):
            if action not in self.action_signature:
                self.action_signature[action] = inspect.signature(action).parameters
            param_dict = {}
            param_list = [{}]
            for p in self.action_signature[action]:
                if p == 'priority':
                    continue
                temp[p] = []
                if p not in params:
                    params.append(p)

                if len(action_space[p]) == 1:
                    for p_dict in param_list:
                        p_dict[p] = list(action_space[p].keys())[0]
                else:
                    new_param_list = []
                    for p_dict in param_list:
                        for key, val in action_space[p].items():
                            p_dict[p] = key
                            new_param_list.append({key: value for key, value in p_dict.items()})
                    param_list = new_param_list
            for p_dict in param_list:
                possible_actions.append(action(**p_dict))

        self.possible_actions = possible_actions
        return len(possible_actions)
