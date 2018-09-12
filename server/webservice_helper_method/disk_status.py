import json

import psutil


def get_disk_usage():
    values = []
    disk_partitions = psutil.disk_partitions(all=True)
    for partition in disk_partitions:
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            device = {'drive_name': partition.device,
                      # 'disk_mount_point': partition.mountpoint,
                      # 'disk_filesystem_type': partition.fstype,
                      # 'disk_mount_type': partition.opts,
                      'disk_total_space': str(usage.total / 10 ** 9) + " GB",
                      'disk_used_space': str(usage.used / 10 ** 9) + " GB",
                      'disk_free_space': str(usage.free / 10 ** 9) + " GB",
                      'disk_usage_percent': str(usage.percent) + " %",
                      }
            # values.append({device['drive_name']: device})
            values.append(device)
        except:
            pass
    return values


#
# def get_disk_usage():
#     values = []
#     with open(r'C:\Users\Administrator\Desktop\server\static\disk.json', 'r') as f:
#         return f.read()


# print(get_disk_usage())
