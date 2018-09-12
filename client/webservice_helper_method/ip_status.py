import subprocess

ip_dict = {}


def get_ip():
    content = (
        subprocess.Popen(r"ipconfig /all", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[
            0]).decode(
        'utf-8').split("\r\n")
    for i in content:
        if ":" in i.rstrip("\n"):
            key = i.split(":")[0].split(".")[0].strip()
            value = i.split(":")[1].strip()
            ip_dict[key] = value

    return ip_dict




#print(get_ip())
