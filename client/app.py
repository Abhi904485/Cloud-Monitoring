import sys

sys.path = ['..'] + sys.path
import os
import subprocess
from flask import Flask, jsonify, redirect, url_for, request
from webservice_helper_method import ip_status, disk_status, all_process_status, network_usage, system_status, \
    memory_status, service_status
import json
from requests import Session
from agent import startup

session = Session()
app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['TEMPLATES_AUTO_RELOAD'] = True


@app.route('/get_ip_details', methods=['GET'])
def get_ip_details():
    response_ip = ip_status.get_ip()
    return jsonify(response_ip)


@app.route('/get_memory_details', methods=['GET'])
def get_memory_details():
    response = memory_status.get_memory_usage()
    return jsonify(response)


@app.route('/get_network_details', methods=['GET'])
def get_network_details():
    response = network_usage.get_network()
    return jsonify(response)


@app.route('/get_disk_details', methods=['GET'])
def get_disk_details():
    response = disk_status.get_disk_usage()
    return jsonify(response)


@app.route('/get_all_process_details', methods=['GET'])
def get_all_process_details():
    response = all_process_status.process_list()
    return jsonify(response)


@app.route('/get_system_details', methods=['GET'])
def get_system_details():
    response = system_status.system_status()
    return jsonify(response)


@app.route('/get_service_details', methods=['GET'])
def get_service_details():
    response = service_status.service_list()
    return jsonify(response)


@app.route('/start_service', methods=['POST'])
def start_service():
    command = request.json['command']
    print(command)
    r, e = subprocess.Popen("net start " + command, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE).communicate()
    result = r.decode('utf-8')
    error = e.decode('utf-8')
    if not error:
        return jsonify({"status": "ok", "message": "{}".format(result)})
    else:
        return jsonify({"status": "error", "message": "{}".format(error)})


@app.route('/stop_service', methods=['POST'])
def stop_service():
    command = request.json['command']
    print(command)
    r, e = subprocess.Popen("net stop " + command, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE).communicate()
    result = r.decode('utf-8')
    error = e.decode('utf-8')
    if not error:
        return jsonify({"status": "ok", "message": "{}".format(result)})
    else:
        return jsonify({"status": "error", "message": "{}".format(error)})


@app.route('/restart_service', methods=['POST'])
def restart_service():
    command = request.json['command']
    print(command)
    r, e = subprocess.Popen("net restart " + command, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE).communicate()
    result = r.decode('utf-8')
    error = e.decode('utf-8')
    if not error:
        return jsonify({"status": "ok", "message": "{}".format(result)})
    else:
        return jsonify({"status": "error", "message": "{}".format(error)})


@app.route('/rdp/<ip>/<username>/<password>/<port>', methods=['GET', 'POST'])
def rdp(ip, username, password, port):
    os.system(r"py -2 " + os.getcwd + os.sep + "my_rdp.py -u " + username + " -p " + password + " " + ip + ":" + port)
    return redirect(url_for('home'))


@app.route('/kill_process', methods=['POST'])
def kill_process():
    process_name = request.json['command']
    if os.system(r"Taskkill /IM " + str(process_name) + " /F") == 0:
        return jsonify(
            {"status": "ok", "message": "You have Successfully terminated process name {} ".format(process_name)})
    else:
        return jsonify({"status": "error",
                        "message": "You do not have proper permission on process name  {} or process is not running ".format(
                            process_name)})


@app.route('/start_process', methods=['POST'])
def start_process():
    process_name = request.json['command']
    modified_string = '"' + process_name + '"'
    try:
        if os.startfile(modified_string) is None:
            return jsonify({"status": "ok"})
    except:
        return jsonify({"status": "error"})


@app.route('/start_or_stop_service', methods=['POST'])
def start_or_stop_service():
    command = request.json['command']
    print(command)
    r, e = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    result = r.decode('utf-8')
    error = e.decode('utf-8')
    if not error:
        return jsonify({"status": "ok", "message": "{}".format(result)})
    else:
        return jsonify({"status": "error", "message": "{}".format(error)})


@app.route('/push_agent', methods=['GET', 'POST'])
def push_agent():
    try:
        agent_json_data = startup.main()
        push_agent_response = session.post("http://192.168.0.100/push_agent", json=agent_json_data)
        json_response = json.loads(push_agent_response.content)
        if json_response['Status'] == "Had Done":
            print(json_response['Message'])
        elif json_response['Status'] == "Doing":
            print(json_response['Message'])
    except:
        agent_json_data = startup.main()
        push_agent_response = session.post("http://192.168.0.100/push_agent", json=agent_json_data)
        json_response = json.loads(push_agent_response.content)
        if json_response['Status'] == "Had Done":
            print(json_response['Message'])
        elif json_response['Status'] == "Doing":
            print(json_response['Message'])


@app.route('/hello', methods=['GET', 'POST'])
def hello():
    return jsonify({"status": "ok"})


if __name__ == '__main__':
    push_agent()
    app.run(host="0.0.0.0", port=4200, debug=True)
