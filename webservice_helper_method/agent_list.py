import json


def get_agents():
    with open(r'D:\Python_hands_on\RAR\static\agents.json', 'r') as f:
        agent_dict = json.load(f)
        return agent_dict
