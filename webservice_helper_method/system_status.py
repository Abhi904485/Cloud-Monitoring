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
    status_dict['running_since'] = boot_time.strftime("%A %d. %B %Y")
    status_dict['os_version'] = os, version
    status_dict['name_cpu_cores'] = name, cores
    status_dict['disk_percent'] = disk_percent
    status_dict['cpu_percent'] = cpu_percent
    status_dict['memory_percent'] = memory_percent
    return status_dict


# print(system_status())
