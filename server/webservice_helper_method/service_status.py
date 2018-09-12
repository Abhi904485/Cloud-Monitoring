import psutil

all_service_list = []


def service_list():
    for service_details in psutil.win_service_iter():
        all_service_list.append(service_details.as_dict())
    return all_service_list

# print(service_list())
