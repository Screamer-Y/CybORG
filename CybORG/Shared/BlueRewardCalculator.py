from collections import namedtuple

from CybORG.Shared import Scenario
from CybORG.Shared.RedRewardCalculator import DistruptRewardCalculator, PwnRewardCalculator
from CybORG.Shared.RewardCalculator import RewardCalculator


HostReward = namedtuple('HostReward','confidentiality availability')

# modification
REWARD_MAX_DECIMAL_PLACES = 1

class ConfidentialityRewardCalculator(RewardCalculator):
    # Calculate punishment for defending agent based on compromise of hosts/data
    def __init__(self, team_name: str, scenario: Scenario, adversary):
        self.scenario = scenario
        self.adversary = adversary
        super(ConfidentialityRewardCalculator, self).__init__(team_name)
        self.infiltrate_rc = PwnRewardCalculator(self.adversary, scenario)
        self.compromised_hosts = {}

    def reset(self):
        self.infiltrate_rc.reset()

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        self.compromised_hosts = {}
        reward = -self.infiltrate_rc.calculate_reward(current_state, action, agent_observations, done)
        self._calculate_compromised_hosts()
        return reward

    def _calculate_compromised_hosts(self):
        for host, value in self.infiltrate_rc.compromised_hosts.items():
            self.compromised_hosts[host] = -1 * value


class AvailabilityRewardCalculator(RewardCalculator):
    # Calculate punishment for defending agent based on reduction in availability
    def __init__(self, team_name: str, scenario: Scenario, adversary):
        super(AvailabilityRewardCalculator, self).__init__(team_name)
        self.adversary = adversary
        self.disrupt_rc = DistruptRewardCalculator(self.adversary, scenario)
        self.impacted_hosts = {}

    def reset(self):
        self.disrupt_rc.reset()

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        self.impacted_hosts = {}
        reward = -self.disrupt_rc.calculate_reward(current_state, action, agent_observations, done)
        self._calculate_impacted_hosts()
        return reward

    def _calculate_impacted_hosts(self):
        for host, value in self.disrupt_rc.impacted_hosts.items():
            self.impacted_hosts[host] = -1 * value

class HybridAvailabilityConfidentialityRewardCalculator(RewardCalculator):
    # Hybrid of availability and confidentiality reward calculator
    def __init__(self, team_name: str, scenario: Scenario, adversary):
        super(HybridAvailabilityConfidentialityRewardCalculator, self).__init__(team_name)
        self.availability_calculator = AvailabilityRewardCalculator(team_name, scenario, adversary)
        self.confidentiality_calculator = ConfidentialityRewardCalculator(team_name, scenario, adversary)

    def reset(self):
        self.availability_calculator.reset()
        self.confidentiality_calculator.reset()

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        reward = self.availability_calculator.calculate_reward(current_state, action, agent_observations, done) \
                 + self.confidentiality_calculator.calculate_reward(current_state, action, agent_observations, done)
        self._compute_host_scores(current_state.keys())
        return reward

    def _compute_host_scores(self, hostnames):
        self.host_scores = {}
        compromised_hosts = self.confidentiality_calculator.compromised_hosts
        impacted_hosts = self.availability_calculator.impacted_hosts
        for host in hostnames:
            if host == 'success':
                continue
            compromised = compromised_hosts[host] if host in compromised_hosts else 0
            impacted = impacted_hosts[host] if host in impacted_hosts else 0
            reward_state = HostReward(compromised,impacted)  
                                    # confidentiality, availability
            self.host_scores[host] = reward_state

# modification
class ReproductionBlueRewardCalculator(RewardCalculator):
    # for Scan get reward from the new part of suspicous host from last scan
    # for RollbackVulnerability, get reward from the absvul from action, and from obs get the 'success'
    # for Restore, if the host is compromised, get a full reward from hostvalue, else a punishment from availability loss
    def __init__(self, agent_name: str, scenario: Scenario):
        super(ReproductionBlueRewardCalculator, self).__init__(agent_name)
        value_dict = {'Medium': 25.0, 'High': 50.0, 'Low':10.0, 'None': 0.0}
        self.host_value = {hostname:value_dict[host.confidentiality_value]+value_dict[host.availability_value] if host.confidentiality_value and host.availability_value else 0.0 for hostname,host in scenario.hosts.items()}
        self.last_scan = []
        self.SCAN_REWARD = 1.0

    def reset(self):
        pass

    def calculate_reward(self, current_state: dict, action: dict, agent_observations: dict, done: bool) -> float:
        if len(action) == 0:
            return
        if 'Sleep' in str(type(action['Blue'])):
            return 0.0
        if 'Scan' in str(type(action['Blue'])):
            print(vars(agent_observations['Blue']))
            new_suspicious_host_len = len(agent_observations['Blue'].data['hostname']) - len(self.last_scan)
            reward = new_suspicious_host_len * self.SCAN_REWARD
            self.last_scan = list(agent_observations['Blue'].data['hostname'])
            return max(round(reward, REWARD_MAX_DECIMAL_PLACES), 0.0)
        if 'RollBack' in str(type(action['Blue'])):
            if agent_observations[self.agent_name].data['success']:
                reward = action['Blue'].selected_vulnerability.bonus - action['Blue'].selected_vulnerability.cost
            else:
                reward = 0.0
            return round(reward, REWARD_MAX_DECIMAL_PLACES)
        if 'Restore' in str(type(action['Blue'])):
            if agent_observations[self.agent_name].data['success']:
                hostname = action['Blue'].hostname
                reward = self.host_value[hostname]
            else:
                reward = 0.0
            return round(reward, REWARD_MAX_DECIMAL_PLACES)
        if 'Invalid' in str(type(action['Red'])):
            return 0.0
        else:
            raise ValueError(f"Unknown action type {type(action['Blue'])}")
