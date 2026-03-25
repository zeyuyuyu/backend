import random
from typing import List

class ConsensusRouter:
    def __init__(self, consensus_nodes: List[str]):
        self.consensus_nodes = consensus_nodes

    def get_next_node(self) -> str:
        """
        Selects the next consensus node to route the request to.
        Implements a weighted round-robin load balancing strategy.
        """
        node_weights = [1] * len(self.consensus_nodes)
        total_weight = sum(node_weights)
        
        # Calculate the cumulative weights
        cumulative_weights = [sum(node_weights[:i+1]) for i in range(len(node_weights))]
        
        # Select the next node based on the cumulative weights
        random_value = random.uniform(0, total_weight)
        for i, weight in enumerate(cumulative_weights):
            if random_value <= weight:
                return self.consensus_nodes[i]
        
        # If all else fails, return a random node
        return random.choice(self.consensus_nodes)
