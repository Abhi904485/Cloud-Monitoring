status_dict_list = []
status_dict = {}


def system_status():
    import psutil
    import platform
    import datetime

    os, name, version, _, _, _ = platform.uname()
    version = version.split('-')[0]
    cores = psutil.cpu_count()
    cpu_percent = psutil.cpu_percent()
    memory_percent = psutil.virtual_memory()[2]
    disk_percent = psutil.disk_usage('/')[3]
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    status_dict['Running Since'] = boot_time.strftime("%A %d. %B %Y")
    status_dict['OS Version'] = version
    status_dict['Cpu Cores'] = cores
    status_dict['Disk Percent'] = str(disk_percent) + " %"
    status_dict['Cpu Percent'] = str(cpu_percent) + " %"
    status_dict['Memory Percent'] = str(memory_percent) + " %"
    return status_dict

# print(system_status())
