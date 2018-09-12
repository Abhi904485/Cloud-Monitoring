import os


def start_process(my_obj):
    ip = my_obj['ip']
    username = my_obj['username']
    password = my_obj['password']
    command = "D:\Python_hands_on\Hackfest\webservice_helper_method\PsExec.exe \\\\" + ip + " -u " + username + " -p " + password + r" -c -f D:\Python_hands_on\Hackfest\webservice_helper_method\iname.bat > D:\Python_hands_on\Hackfest\webservice_helper_method\success.txt"
    print(command)
    if os.system(command) == 0:
        return 0
    else:
        return -1
