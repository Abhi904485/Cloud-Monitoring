import sys
sys.path = ['..']+sys.path
import json
import os
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask import Flask, render_template, flash, redirect, url_for, request, jsonify
from flask_debugtoolbar import DebugToolbarExtension
from flask_login import LoginManager
from flask_login import login_user, current_user, logout_user, login_required
from forms import LoginForm, RegistrationForm
from requests import Session

session = Session()
app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
import object_to_json

login_manager = LoginManager(app)
login_manager.login_view = 'login'
db = SQLAlchemy(app)

from models import User, Agents

db.create_all()
bcrypt = Bcrypt(app)
toolbar = DebugToolbarExtension(app)


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/home")
def home():
    if current_user.is_authenticated:
        for agent_ip in object_to_json.get_ip():
            try:
                agent_ip_response = session.get("http://" + agent_ip['ip'] + ":4200/hello", timeout=(1, 2))
                json_response = json.loads(agent_ip_response.content)
                if json_response['status'] == "ok":
                    pass
            except:
                flash("Remote Agent {} is down please do the needful ".format(agent_ip['hostname']), 'danger')
        return render_template('home.html', computers=object_to_json.get_agent())
    else:
        return redirect(url_for('login'))


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        if User.query.filter_by(username=username).first():
            flash('That username is already taken Please Choose Other One', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('That email is already taken Please choose Other one', 'danger')
        else:
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)

            db.session.add(user)
            db.session.commit()
            flash('Your Account has been Created! You are now able to login', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@login_required
@app.route("/details/<ip>/<guid>/<username>/<password>/<port>/<hostname>")
def details(ip, guid, username, password, port, hostname):
    if current_user.is_authenticated:
        try:
            return render_template('details.html', username=username, password=password, port=port,
                                   ip=ip, guid=guid, hostname=hostname,
                                   title='details', ip_details=get_ip_details(ip),
                                   system_details=get_system_details(ip), disk_details=get_disk_details(ip),
                                   memory_details=get_memory_details(ip),
                                   network_details=get_network_details(ip),
                                   process_details=get_all_process_details(ip),
                                   service_details=get_service_details(ip),
                                   )
        except:
            flash("Remote agent {} is down , Please do the needful".format(hostname), 'danger')
            return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))


@app.route('/get_ip_details<system_ip>', methods=['GET'])
def get_ip_details(system_ip):
    response_ip = session.get("http://" + system_ip + ":4200/get_ip_details", timeout=(1, 2))
    return json.loads(response_ip.content)


@app.route('/get_memory_details<system_ip>', methods=['GET'])
def get_memory_details(system_ip):
    response_memory = session.get("http://" + system_ip + ":4200/get_memory_details", timeout=(1, 2))
    return json.loads(response_memory.content)


@app.route('/get_network_details<system_ip>', methods=['GET'])
def get_network_details(system_ip):
    response_network = session.get("http://" + system_ip + ":4200/get_network_details", timeout=(1, 2))
    return json.loads(response_network.content)


@app.route('/get_disk_details<system_ip>', methods=['GET'])
def get_disk_details(system_ip):
    response_disk = session.get("http://" + system_ip + ":4200/get_disk_details", timeout=(1, 2))
    return json.loads(response_disk.content)


@app.route('/get_all_process_details<system_ip>', methods=['GET'])
def get_all_process_details(system_ip):
    response_process = session.get("http://" + system_ip + ":4200/get_all_process_details", timeout=(1, 2))
    return json.loads(response_process.content)


@app.route('/get_system_details<system_ip>', methods=['GET'])
def get_system_details(system_ip):
    response_system = session.get("http://" + system_ip + ":4200/get_system_details", timeout=(1, 2))
    return json.loads(response_system.content)


@app.route('/get_service_details<system_ip>', methods=['GET'])
def get_service_details(system_ip):
    response_service = session.get("http://" + system_ip + ":4200/get_service_details", timeout=(1, 2))
    return json.loads(response_service.content)


@app.route('/start_service/<ip>/<service_name>/<hostname>', methods=['GET', 'POST'])
def start_service(ip, service_name, hostname):
    start_service_status = session.post("http://" + ip + ":4200/start_service", json={"command": service_name})
    json_response = json.loads(start_service_status.content)
    if json_response['status'] == "ok":
        flash(json_response['message'] + "on agent " + hostname, 'success')
    else:
        flash(json_response['message'] + "on agent " + hostname, 'danger')
    return redirect(url_for('home'))


@app.route('/stop_service/<ip>/<service_name>/<hostname>', methods=['GET', 'POST'])
def stop_service(ip, service_name, hostname):
    stop_service_status = session.post("http://" + ip + ":4200/stop_service", json={"command": service_name})
    json_response = json.loads(stop_service_status.content)
    if json_response['status'] == "ok":
        flash(json_response['message'] + "on agent " + hostname, 'success')
    else:
        flash(json_response['message'] + "on agent " + hostname, 'danger')
    return redirect(url_for('home'))


@app.route('/restart_service/<ip>/<service_name>/<hostname>', methods=['GET', 'POST'])
def restart_service(ip, service_name, hostname):
    restart_service_status = session.post("http://" + ip + ":4200/stop_service", json={"command": service_name})
    json_response = json.loads(restart_service_status.content)
    if json_response['status'] == "ok":
        flash(json_response['message'] + "on agent " + hostname, 'success')
    else:
        flash(json_response['message'] + "on agent " + hostname, 'danger')
    return redirect(url_for('home'))


@app.route('/rdp/<ip>/<username>/<password>/<port>', methods=['GET', 'POST'])
def rdp(ip, username, password, port):
    os.system(
        r"C:\Python27\python.exe"+os.getcwd()+os.sep+"my_rdp.py -u " + username + " -p " + password + " " + ip + ":" + port)
    return redirect(url_for('home'))


@app.route('/action', methods=['GET', 'POST'])
def action():
    obj1 = request.form.to_dict(flat=False)
    print(obj1)
    kill_process_name = obj1['kill_process_exe_path']
    start_process_name = obj1['start_process_exe_path']
    manage_services = obj1['manage_service']
    try:
        machine_ips = obj1['check_list']
        if machine_ips[0]:
            if len(kill_process_name) == 1:
                for process_name in kill_process_name:
                    if process_name:
                        for system_ip in machine_ips:
                            ip_to_host = object_to_json.get_ip_host(system_ip)[0]
                            try:
                                kill_process_status = session.post("http://" + system_ip + ":4200/kill_process",
                                                                   json={"command": process_name})
                                json_response = json.loads(kill_process_status.content)

                                if json_response['status'] == "ok":
                                    flash(json_response['message'] + "on agent " + ip_to_host['hostname'], 'success')
                                else:
                                    flash(json_response['message'] + "on agent " + ip_to_host['hostname'], 'danger')
                            except:
                                flash("Remote agent {} is down . please do the needful.".format(ip_to_host['hostname']),
                                      'danger')

            if len(start_process_name) == 1:
                for process_name in start_process_name:
                    if process_name:
                        for system_ip in machine_ips:
                            ip_to_host = object_to_json.get_ip_host(system_ip)[0]
                            try:
                                start_process_status = session.post(
                                    "http://" + system_ip + ":4200/start_process", json={"command": process_name})
                                # print(process_name)
                                json_response = json.loads(start_process_status.content)
                                # print(json_response)

                                if json_response['status'] == "ok":
                                    flash(
                                        process_name + " Successfully Started " + "on agent " + ip_to_host['hostname'],
                                        'success')
                                else:
                                    flash(
                                        "There is Some problem in Starting process " + process_name + " on agent " +
                                        ip_to_host['hostname'],
                                        'danger')
                            except:
                                flash("Remote agent {} is down . please do the needful.".format(ip_to_host['hostname']),
                                      'danger')

            if len(manage_services) == 1:
                for service in manage_services:
                    if service:
                        for system_ip in machine_ips:
                            ip_to_host = object_to_json.get_ip_host(system_ip)[0]
                            try:
                                start_or_stop_service = session.post(
                                    "http://" + system_ip + ":4200/start_or_stop_service", json={"command": service})
                                json_response = json.loads(start_or_stop_service.content)
                                print(json_response)
                                if json_response['status'] == "ok":
                                    flash(json_response['message'] + "on agent " + ip_to_host['hostname'], 'success')
                                else:
                                    flash(json_response['message'] + "on agent " + ip_to_host['hostname'], 'danger')
                            except:
                                flash("Remote agent {} is down . please do the needful.".format(ip_to_host['hostname']),
                                      'danger')

            return redirect(url_for('home'))
    except:
        flash("Please Select at least one Workstation ", 'danger')
        return redirect(url_for('home'))


@app.route('/kill_process/<ip>/<process_name>/<hostname>', methods=['GET', 'POST'])
def kill_process(ip, process_name, hostname):
    kill_process_status = session.post("http://" + ip + ":4200/kill_process", json={"command": process_name})
    json_response = json.loads(kill_process_status.content)
    if json_response['status'] == "ok":
        flash(json_response['message'] + "on agent " + hostname, 'success')
    else:
        flash(json_response['message'] + "on agent " + hostname, 'danger')
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/push_agent', methods=['GET', 'POST'])
def push_agent():
    username = request.json['username']
    hostname = request.json['hostname']
    ip = request.json['ip']
    password = request.json['password']
    port = request.json['port']
    guid = request.json['guid']
    os_agent = request.json['os']
    running = request.json['running_since']

    if Agents.query.filter_by(guid=guid).first():
        return jsonify({"Status": "Had Done", "Message": "Agent is Already registered"})
    else:
        agents = Agents(guid=guid, ip=ip, username=username, password=password, port=port, hostname=hostname,
                        os=os_agent, running=running)
        db.session.add(agents)
        db.session.commit()
        return jsonify({"Status": "Doing", "Message": "Agent is Registering"})


@app.route('/add_agent', methods=['GET', 'POST'])
def add_agent():
    user_name = request.json['username']
    hostname = request.json['hostname']
    ip = request.json['ip']
    password = "novell@123"
    port = "3389"
    guid = request.json['guid']
    agents = Agents(guid=guid, ip=ip, username=user_name, password=password, port=port, hostname=hostname)
    db.session.add(agents)
    db.session.commit()


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)
