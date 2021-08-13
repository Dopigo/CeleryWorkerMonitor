import glob
import requests
import socket

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
    #print(url)
    url = url.replace("amqp", "http").replace("5672","15672").replace("\n", "")
    return url

def get_consumer_queues(server_url,ips):
    #print(server_url+"api/consumers")
    response = requests.get(server_url+"api/consumers")
    result = response.json()
    queues = []
    for i in result:
        ip = i["channel_details"]["peer_host"]
        if(ip in ips):
            queues.append(i["queue"]["name"])
    return queues


def get_ip_addresses():
    external = requests.get("https://api.ipify.org").text
    s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    s.connect(("8.8.8.8",80))
    local = s.getsockname()[0]
    ips = [external,local]
    #print(ips)
    s.close()
    return ips

def check_queues():
    service_queues = get_queue_names(serviceFiles)
    queues_running = get_consumer_queues(get_server_info(),get_ip_addresses())
    #print(service_queues)
    #print(queues_running)
    result = True
    for q in service_queues:
        if not(q in queues_running):
            print("Queue: "+q+" not found")
            result = False
        print("Queue: "+q+" was found")
    if(result): print("Success")
    else: print("Error")

check_queues()
#get_server_info()
