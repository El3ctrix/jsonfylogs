import sys, getopt
from configparser import ConfigParser
import requests
import time
import os
import json

def send_json(json_list):
    """
    This function will send the json to the server
    """
    print('Sending JSON to server...')
    config_object = ConfigParser()
    config_object.read("config.ini")
    api = config_object["API"]
    url = api["url"]
    headers = {'accept': 'application/json', 'X-Scope-OrgID': 'docker',  'Content-Type': 'application/json'}
    for record in json_list:
        data = json.dumps({"streams": [{"stream": {"Aplication": "Malware", 
        "fecha_hora": record["Fecha y hora"], 
        "alerta": record["Alerta/Anomalia"], 
        "usuario": record["Usuario"], 
        "IPOrigen": record["IPsource"], 
        "IPDestino": record["IPdestination"], 
        "Actividad": record["Actividad"], 
        "Descripcion": record["Descripcion"], 
        "Permisos": record["Permisos"]},
        "values":[[str(time.time_ns()), "{} {} {} -> {} {}".format(record["Fecha y hora"], 
        record["Alerta/Anomalia"], record["IPsource"], record["IPdestination"], 
        record["Descripcion"])]]}]}, indent = 4)
        r = requests.post(url, headers=headers, data=data)
    print('All logs sent.')

def suricata_jsonfylogs():
    """
    This function will convert all suricata logs to json using the eve.json file
    """
    print('Converting all suricata logs to JSON...')
    # log format: Fecha y hora, Alerta/Anomalia, Usuario, IPsource, IPdestination, Actividad, Descripcion, Permisos "signature"
    # "signature" is the desired field in the eve.json file
    json_list = []
    config_object = ConfigParser()
    config_object.read("config.ini")
    suricatapath = config_object["MAINPATH"]["suricata_path"]
    last_valid_line = config_object["LINE"]["last_line"]
    flag = False
    if(os.path.basename(suricatapath) == 'suricata1.log'):
        print('Suricata path is valid.')
        f = open(suricatapath, "r")
        line = f.readline()
        if(not config_object["LINE"]["last_line"] == 'Nothing'):
            while line:
                if (not line.find(last_valid_line) == -1):
                    flag = True
                    line = f.readline()
                    break
                line = f.readline()
        if(not flag):
            f.seek(0)
            line = f.readline()
        while line:
            if(not line.find('{') == -1):
                index = line.index('{')
                record = json.loads(line[index:])
                last_valid_line = line[0:index]
                print(last_valid_line)
                if(record['event_type'] == 'alert'):
                    json_list.append({"Fecha y hora": record['timestamp'], 
                    "Alerta/Anomalia": record['event_type'], "Usuario": "Suricata", 
                    "IPsource": record['src_ip'], "IPdestination": record['dest_ip'], 
                    "Actividad": record['alert']['action'], "Descripcion": record['alert']['signature'], "Permisos": "None"})
            line = f.readline()
        if(not last_valid_line == 'Nothing'):
            config_object['LINE'] = {
                'last_line': last_valid_line
            }
            with open('config.ini', 'w') as conf:
                config_object.write(conf)
        f.close()
            
    with open('suricata.json', 'w') as f:
        json.dump(json_list, f, ensure_ascii=False, indent = 4)
    if(len(json_list) > 0):
        send_json(json_list)
    else:
        print("The log file is empty")

def checK_configfile(mode, arg):
    """
    This function will check if the config file exists and if it has the correct configuration
    """
    options = {'API': 'url', 'MAINPATH': 'suricata_path'}
    if(verify_configfile()):
        config_object = ConfigParser()
        config_object.read("config.ini")
        config_option = config_object[mode]
        if(config_option[options[mode]] != arg):
            print('Warning: Config file does not match with the config provided.')
            print('Changing configuration...')
            change_configfile(mode, arg)
            print('Configuration changed.')
    else:
        if not os.path.exists('config.ini'):
            print('Warning: Config file does not exist , creating a new file.')
            open('config.ini', 'w').close()
        config_object = ConfigParser()
        config_object.read("config.ini")
        config_object[mode] = {
            options[mode]: arg
        }
        with open('config.ini', 'w') as conf:
            config_object.write(conf)

def change_configfile(mode, new_option):
    """
    This function will change the path in the config file
    """
    options = {'API': 'url', 'MAINPATH': 'suricata_path'}
    config_object = ConfigParser()
    config_object.read("config.ini")
    config_object[mode] = {
        options[mode]: new_option
    }
    with open('config.ini', 'w') as conf:
        config_object.write(conf)

def verify_configfile():
    """
    This function will verify if the config file exists and if it has the path to the logs
    """
    exists = True
    if os.path.exists('config.ini'):
        config_file = ConfigParser()
        config_file.read('config.ini')
        sections = config_file.sections()
        if len(sections) == 0 or 'MAINPATH' not in sections or 'API' not in sections:
            exists = False
    else:
        print('Config file does not exist.')
        exists = False
    return exists

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"ha:p:",["help","api=","path="])
    except getopt.GetoptError:
        print('Invalid arguments.')
        print('Usage: jsonfylogs.py [-a | --api]  [-p | --path <path>]')
        sys.exit(2)
    if len(opts) != 0:
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print('Usage: jsonfylogs.py [-a | --api]  [-p | --path <path>]')
                sys.exit()
            elif opt in ("-a", "--api"):
                # If this option is selected, is necesary to have in the config file the url of the api
                checK_configfile('API', arg)
            elif opt in ("-p", "--path"):
                # This option will be used to specify the path to the logs
                checK_configfile('MAINPATH', arg)
            else:
                print('Invalid arguments.')
                print('Usage: jsonfylogs.py [-a | --api]  [-p | --path <path>]')
                sys.exit(2)
    else:
        if os.path.exists('config.ini'):
            if(verify_configfile()):
                suricata_jsonfylogs()
            else:
                print('Configuration file is not valid.')
                print('Run the script with the -p and -a option and specify the path to the logs and the URL for the API.')
        else:
            print('Config file does not exist, run the script with the -p and -a option and specify the path to the logs.')
            print('Usage: jsonfylogs.py [-a | --api]  [-p | --path <path>]')
            sys.exit(2)

if __name__ == "__main__":
    main(sys.argv[1:])
