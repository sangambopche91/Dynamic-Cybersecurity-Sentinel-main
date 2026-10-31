class RiskScorer:
    def __init__(self):
        self.base_risk = {
            "Normal": 0,
            "Analysis": 55,
            "Reconnaissance": 60,
            "Fuzzers": 65,
            "Generic": 70,
            "Exploits": 80,
            "DoS": 85,
            "Backdoor": 90,
            "Shellcode": 90,
            "Worms": 95
        }