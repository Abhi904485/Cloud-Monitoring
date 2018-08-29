import time

import psutil

list_of_process = []


def process_list():
    for process_details in psutil.process_iter():
        list_of_process.append(
            {'process_id': process_details.ppid(), 'process_name': process_details.name(),
             # 'process_cpu_times': process_details.cpu_times(),
             'process_cpu_percent': process_details.cpu_percent(),
             # 'process_memory_info': process_details.memory_info(),
             'process_memory_percentage': process_details.memory_percent(),
             'process_creation_time': time.strftime('%Y-%m-%d %H:%M:%S %p',
                                                    time.localtime(
                                                        process_details.create_time())),
             'process_status': process_details.status()
             })

    return list_of_process


# for i in process_list():
#     for j in i:
#         print(j, i[j])

# print(process_list())
