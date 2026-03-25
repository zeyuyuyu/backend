import random
import time

class ConsensusRouter:
    def __init__(self, nodes):
        self.nodes = nodes
        self.leader = None
        self.term = 0
        self.voted_for = None

    def elect_leader(self):
        candidates = [node for node in self.nodes if node.is_alive()]
        if not candidates:
            return None

        self.term += 1
        self.voted_for = None

        # Weighted voting based on node resources
        votes = {candidate: candidate.resources for candidate in candidates}
        self.leader = max(votes, key=votes.get)
        return self.leader

    def handle_request(self, request):
        if self.leader is None or not self.leader.is_alive():
            self.elect_leader()

        if self.leader == self.nodes[random.randint(0, len(self.nodes) - 1)]:
            # Leader handles the request
            self.leader.process_request(request)
        else:
            # Forward the request to the leader
            self.leader.forward_request(request)

    def add_node(self, node):
        self.nodes.append(node)

    def remove_node(self, node):
        self.nodes.remove(node)
