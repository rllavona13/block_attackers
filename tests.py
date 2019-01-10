from flask import Flask, render_template, redirect, url_for, request
from jnpr.junos import Device
from jnpr.junos.utils.config import Config
import json


app = Flask(__name__)

config_file = open('auth.json')
config = json.load(config_file)
config_file.close()


@app.route('/', methods=['GET', 'POST'])
def block_form():

    if "commit" in request.form:

        compares = []

        for hosts in config['ip']:
            dev = Device(host=hosts, user="", password="", port=22)
            dev.open()
            cfg = Config(dev, mode='private')
            cfg.load('set policy-options prefix-list attackers-list ' + (request.form['attacker']), format='set')
            compares.append([hosts, cfg.diff().strip()])
            cfg.commit()
            dev.close()
        return render_template("attacker_commit.html", compares=compares)

    elif "delete" in request.form:

        compares = []

        for hosts in config['ip']:
            dev = Device(host=hosts, user=config['username'], password=config['password'], port=22)
            dev.open()
            cfg = Config(dev, mode='private')
            cfg.load('delete policy-options prefix-list attackers-list ' + (request.form['a_delete']), format='set')
            compares.append([hosts, cfg.diff().strip()])
            cfg.commit()
            dev.close()
        return render_template("attacker_commit.html", compares=compares)

    elif "show" in request.form:
        for hosts in config['ip']:
            dev = Device(host=hosts, user=config['username'], password=config['password'], port=22)
            dev.open()
            dev.close()
        return render_template("attacker_commit.html")

    else:
        return render_template("attackers_list.html")


@app.route('/attacker_commit', methods=['GET', 'POST'])
def block_commit():

    if "back" in request.submit:
        return render_template('attackers_list.html')
    else:
        return render_template('attackers_list.html')


if __name__ == '__main__':

    app.run(port=5000, debug=True)
