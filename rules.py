class RuleEngine:
    def __init__(self):
        self.blocked = set()

    def block_domain(self, domain):
        self.blocked.add(domain.lower())

    def allow(self, pkt_info):
        domain = pkt_info.get("domain")

        if domain:
            domain = domain.lower()

            for blocked_domain in self.blocked:
                if blocked_domain in domain:
                    return False

        return True