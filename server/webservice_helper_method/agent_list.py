import json


def get_agents():
    with open(r'C:\Users\Administrator\Desktop\server\static\agents.json', 'r') as f:
        agent_dict = json.load(f)
        return agent_dict
