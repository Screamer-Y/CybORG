## The following code contains work of the United States Government and is not subject to domestic copyright protection under 17 USC § 105.
## Additionally, we waive copyright and related rights in the utilized code worldwide through the CC0 1.0 Universal public domain dedication.
import copy
from datetime import datetime
from ipaddress import IPv4Address
from math import sqrt

import networkx as nx
from networkx import connected_components

from CybORG.Shared import Scenario, CybORGLogger
from CybORG.Shared.Enums import SessionType
from CybORG.Shared.Observation import Observation
from CybORG.Simulator.Drone import Drone
from CybORG.Simulator.Host import Host
from CybORG.Simulator.Process import Process
from CybORG.Simulator.Session import Session
from CybORG.Simulator.Subnet import Subnet

from CybORG.Simulator.State import State
from typing import List, Dict
from CybORG.ReproductionExtension.Simulator.AbstractVulnerability import AbstractVulnerability


class StateExtension(State):
    """
	Add a dict {host_id: List[AbstractVulnerability]} to achieve Abstract Action.
    """
    def __init__(self, scenario: Scenario, np_random, host_absvul_map: Dict[str,List[AbstractVulnerability]]):
        super().__init__(scenario, np_random)
        self.host_absvul_map = host_absvul_map

    # 后面再加功能
    def get_host_absvul_map(self):
        return {key:[v.vulnerability_id for v in values] for key,value in self.host_absvul_map.items()}

    def get_host_absvul_dict(self):
        return self.host_absvul_map


