import os

from flask import Flask, jsonify, render_template, flash, redirect, url_for, request
from flask_debugtoolbar import DebugToolbarExtension
from forms import LoginForm, RegistrationForm
from webservice_helper_method import ip_status, disk_status, all_process_status, network_usage, system_status, \
    memory_status, start_service_remote, service_status, stop_service, agent_list

from threading import Thread

app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
toolbar = DebugToolbarExtension(app)
computer_details = [
    {
        'Networking Details': '',
        'username': 'Administrator',
        'passoword': 'test@123'
    },

]


@app.route("/")
def index():
    return render_template('index.html')


@app.route("/home")
def home():
    return render_template('home.html', computers=agent_list.get_agents())


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        flash('Account created for {}!'.format(form.username.data), 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.email.data == 'admin@blog.com' and form.password.data == 'password':
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/details")
def details():
    return render_template('details.html', title='details', ip_details=get_ip_details(),
                           system_details=get_system_details(), disk_details=get_disk_details(),
                           memory_details=get_memory_details(), process_details=get_all_process_details(),
                           service_details=get_service_details(), network_details=get_network_details())


@app.route('/get_ip_details', methods=['GET'])
def get_ip_details():
    response_ip = ip_status.get_ip()
    return response_ip


@app.route('/get_memory_details', methods=['GET'])
def get_memory_details():
    response = memory_status.get_memory_usage()
    return response


@app.route('/get_network_details', methods=['GET'])
def get_network_details():
    response = network_usage.get_network()
    return response


@app.route('/get_disk_details', methods=['GET'])
def get_disk_details():
    response = disk_status.get_disk_usage()
    return response


@app.route('/get_all_process_details', methods=['GET'])
def get_all_process_details():
    response = all_process_status.process_list()
    return response


@app.route('/get_system_details', methods=['GET'])
def get_system_details():
    response = system_status.system_status()
    return response


@app.route('/get_service_details', methods=['GET'])
def get_service_details():
    response = service_status.service_list()
    return response


@app.route('/start_service', methods=['POST'])
def start_service():
    data = {
        'process_id': request.json['id'],
        'process_name': request.json['name'],
        'ip': request.json['ip'],
        'username': request.json['username'],
        'password': request.json['password']
    }
    if start_service_remote.start_process(data) == 0:
        return "Success"
    else:
        return "Failure"


@app.route('/stop_service,', methods=['GET', 'POST'])
def stop_service():
    my_obj = []
    data = {
        'process_id': request.json['id'],
        'process_name': request.json['name'],
        'ip': request.json['ip'],
        'username': request.json['username'],
        'password': request.json['password']
    }
    my_obj.append(data)
    if stop_service.start(my_obj) == 0:
        return "Success"
    else:
        return "Failure"


@app.route('/rdp', methods=['GET', 'POST'])
def rdp():
    os.system(
        "py -2 D:\\Python_hands_on\\RAR\\webservice_helper_method\\my_rdp.py -u Administrator -p novell@123 10.200.144.5:3389")
    return redirect(url_for('details'))


@app.route('/kill_process', methods=['GET', 'POST'])
def kill_process():
    searchword = request.args.get('name', '')
    print(searchword)


if __name__ == '__main__':
    app.run()
