from psutil import virtual_memory

memory_usage_dict = {}


def get_memory_usage():
    memory_usage_dict['total_memory'] = str(virtual_memory().total / 10 ** 9) + " GB"
    memory_usage_dict['available_memory'] = str(virtual_memory().available / 10 ** 9) + " GB"
    memory_usage_dict['used_memory'] = str(virtual_memory().used / 10 ** 9) + " GB"
    memory_usage_dict['usage_memory_percent'] = str(virtual_memory().percent) + " %"
    return memory_usage_dict


# print(get_memory_usage())
