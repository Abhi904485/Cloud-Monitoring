from random import randint
import getpass
import os
import socket
import platform
import datetime
import psutil

PATH = os.getcwd()

def random_with_n_digits(n):
    range_start = 10 ** (n - 1)
    range_end = (10 ** n) - 1
    return randint(range_start, range_end)

def read_guid():
    with open(PATH + os.sep + "guid.txt", 'r') as f:
        guid_con = f.read().strip()
        f.close()
        return guid_con

def create_guid_file():
    if os.path.exists(PATH + os.sep + "guid.txt"):
        return read_guid()
    else:
        with open(PATH+ os.sep + "guid.txt", 'w') as f:
            guid = str(random_with_n_digits(10))
            f.write(guid)
            return read_guid()

    
def get_username():
    username = getpass.getuser()
    return str(username)

def get_hostname():
    return str(socket.gethostname())

def get_ip():
    return str(socket.gethostbyname(socket.gethostname()))

def get_port():
    return "3389"

def get_password():
    return "novell@123"

def get_os():
    os, _ , version, _, _, _ = platform.uname()
    return str(os + " " +version)

def get_boot_time():
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    return str(boot_time.strftime("%A %d. %B %Y"))

def main():
    agent_details_json = dict()
    agent_details_json['username'] = get_username()
    agent_details_json['guid'] = create_guid_file()
    agent_details_json['hostname']= get_hostname() 
    agent_details_json['ip'] = get_ip()
    agent_details_json['password'] = get_password()
    agent_details_json['port'] = get_port()
    agent_details_json['os']  = get_os()
    agent_details_json['running_since'] = get_boot_time()
    return agent_details_json

     

# print (main())
