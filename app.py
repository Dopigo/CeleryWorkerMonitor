import glob
import requests
import socket
from urllib.parse import urlparse

path = "/etc/systemd/system/celery"  #change directory path
serviceFiles = glob.glob(path+"*.service")

def get_queue_names(service_files):
    queues = []
    for fl in service_files:
        file = open(fl, 'r')
        content = file.readlines()
        if content:
            for line in content:
                if line.startswith("ExecStart"):
                    if (line.find('-Q') > 0):
                        queue_name = line.split('-Q')[1].split()[0]
                        queues.append(queue_name)
                        #print(fl + "  -  " + queue_name)
    return queues


def get_server_info():
    server = open("/etc/conf.d/dopigo",'r') #change directory path
    info = server.readlines()
    url = ""
    for line in info:
        if(line.startswith("DOPIGO_BROKER_URL")):
            url = line.split('=')[1]
    url = url.replace("amqp", "http").replace("5672","15672").replace("\n", "")
    urlCopy = url.split("//")
    url = urlCopy[0]+"//"+urlCopy[1]+"/"+urlCopy[2]
    return url


def get_consumer_queues(server_url,ips):
    response = requests.get(server_url+"api/consumers")
    result = response.json()
    if response.status_code > 300:
        raise ValueError("Queue listesi alınamadı: {}".format(server_url))
    else:
        print("Connected to "+server_url+"api/consumers")
        queues = []
        for i in result:
            print(i["channel_details"]["peer_host"] + "  -  " + i["queue"]["name"])
            ip = i["channel_details"]["peer_host"]
            if(ip in ips):
                queues.append(i["queue"]["name"])
        print("")
        return queues


def get_ip_addresses(hostname):
    external = requests.get("https://api.ipify.org")
    if(external.status_code >=300):
        raise ConnectionError("Could not connect to https://api.ipify.org")
    else: external = external.text
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.connect((hostname,80))
    local = s.getsockname()[0]
    ips = [external,local]
    print("IP Adresses: ")
    print(ips)
    print("")
    s.close()
    return ips

def check_queues():
    service_queues = get_queue_names(serviceFiles)
    url = get_server_info()
    hostname = urlparse(url).hostname
    queues_running = get_consumer_queues(url,get_ip_addresses(hostname))
    print("Queues from the services: ")
    print(service_queues)
    print("Queues running: ")
    print(queues_running)
    result = True
    for q in service_queues:
        if not(q in queues_running):
            print("Queue: "+q+" was not found")
            result = False
        else:
            print("Queue: "+q+" was found")
    if(result):
        print("Success")
    else:
        print("Error")

check_queues()
