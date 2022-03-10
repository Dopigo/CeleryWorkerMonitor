#!/usr/bin/env python3
# -- coding: utf-8 --

import glob
import argparse
import os
import socket
import logging
import subprocess
from urllib.parse import urlparse
from os import environ

import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

parser = argparse.ArgumentParser()

parser.add_argument(
    "-l",
    "--log-level",
    default="error",
    help="Provide logging level. "
         "Example --log-level=debug. Default value is set to warning.",
)

parser.add_argument(
    "-dnssm",
    "--do-not-send-slack-message",
    action="store_true",
    help="Inform Slack channel regarding the errors. Default is True"
)

arguments = parser.parse_args()

levels = {
    'critical': logging.CRITICAL,
    'error': logging.ERROR,
    'warning': logging.WARNING,
    'info': logging.INFO,
    'debug': logging.DEBUG,
}

level = levels.get(arguments.log_level.lower())

if level is None:
    raise ValueError(
        f"Inappropriate value for --log-level: {arguments.log_level}"
        f" -- must be one of: {' | '.join(levels.keys())}"
    )

logging.basicConfig(
    filename="/var/log/celery_worker_monitor.log",
    filemode="a",
    format="%(asctime)s - %(message)s",
    level=level
)

service_file_path = "/etc/systemd/system/"
service_file_name_pattern = "celery*.service"
service_files = glob.glob(service_file_path + service_file_name_pattern)


def get_queue_names():
    queues = []
    for service_file in service_files:
        try:
            with open(service_file, 'r') as file:
                content = file.readlines()
                if content:
                    for line in content:
                        flag = False
                        if line.startswith("ExecStart"):
                            if line.find('-Q') > 0:
                                logging.debug(f"For {service_file}: ")
                                queue_name = line.split('-Q')[1].split()[0]
                                logging.debug(f"queue_name => {queue_name}")
                                service_path = service_file.split("/")
                                logging.debug(f"service_path => {service_path}")
                                service_name = service_path[-1]
                                logging.debug(f"service_name => {service_name}")
                                queues.append(f"{queue_name},{service_name}")

                                flag = True
                                break
                    # if ExecStart is not found, log to the file
                    if not flag:
                        logging.error(f"ExecStart could not found in {service_file}.")
        except Exception as uee:
            logging.debug(uee)
            logging.exception(f"{service_file} could not opened.")

    return queues


def get_server_info():
    try:
        flag = False
        with open("/etc/conf.d/dopigo", 'r') as server:
            info = server.readlines()
            url = ""
            for line in info:
                if line.startswith("DOPIGO_BROKER_URL"):
                    url = line.split('=')[1]
                    flag = True
                    break

            # if DOPIGO_BROKER_URL is not found
            if not flag:
                logging.warning("Could not find DOPIGO_BROKER_URL in /etc/conf.d/dopigo")

            url = url.replace("amqp", "http").replace("5672", "15672").replace("\n", "")
            url_copy = url.split("//")
            url = f"{url_copy[0]}//{url_copy[1]}/{url_copy[2]}"

            return url
    except Exception:
        message = "/etc/conf.d/dopigo could not opened."
        logging.exception(message)
        raise IOError(message)


def get_consumer_queues(server_url, ips):
    server_url = f"{server_url}api/consumers"
    logging.debug(f"Sending GET request to {server_url}")
    response = requests.get(server_url)
    logging.debug(f"GET request has been sent to {server_url} with the status code of {response.status_code}")
    result = response.json()
    if response.status_code > 300:
        message = f"Queue listesi alınamadı: {server_url}"
        logging.error(message)
        raise ValueError(message)

    message = f"Connection to {server_url} is successful. JSON data has been retrieved."
    logging.debug(message)
    print(message)
    queues = []
    logging.debug(f"{server_url} adresinden dönen response: {result}")
    logging.debug(f"{server_url}' dönen response for-loop ile iterate ediliyor:")
    for i in result:
        logging.debug(i)
        if i["channel_details"]:
            print(i["channel_details"]["peer_host"] + "  -  " + i["queue"]["name"])
            ip = i["channel_details"]["peer_host"]
            if ip in ips:
                queues.append(i["queue"]["name"])
    logging.debug("for-loop iterasyonu bitti.")
    logging.debug(f"Queues are retrieved from {server_url}. The retrieved queues are: {queues}")
    return queues


def get_ip_addresses(hostname):
    logging.debug("Sending GET request to ipify...")
    external = requests.get("https://api.ipify.org")
    logging.debug(f"GET request has been sent to ipify with the status code of {external.status_code}")
    if external.status_code > 300:
        message = "Could not connect to https://api.ipify.org"
        logging.error(message)
        raise ConnectionError(message)
    else:
        external = external.text

    logging.debug("Connection to ipify is successfull.")
    logging.debug("Creating a socket...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    logging.debug(f"Attempting to connect {hostname} on port 80.")
    s.connect((hostname, 80))
    logging.debug(f"The connection has been established on {hostname}:80")
    local = s.getsockname()[0]
    ips = [external, local]
    logging.debug("IP Addresses are retrieved: {ips}. Closing the socket.")
    print(f"IP Addresses:\n{ips}")
    s.close()
    return ips


def get_hostname():
    logging.debug("Attempting to get server url...")
    url = get_server_info()
    logging.debug(f"Server url is successfully retrieved: {url}")
    hostname = urlparse(url).hostname
    logging.debug(f"Hostname of {url} is {hostname}")

    return hostname


def check_queues():
    services_and_queues = get_queue_names()
    service_queues = []
    service_names = []
    for service_and_queue in services_and_queues:
        names = service_and_queue.split(",")
        service_queues.append(names[0])
        service_names.append(names[1])

    logging.debug(f"Retrieved queues: {service_queues}")
    logging.debug(f"Retrieved services: {service_names}")

    logging.debug("Attempting to get server url...")
    url = get_server_info()
    logging.debug(f"Server url is successfully retrieved: {url}")
    hostname = urlparse(url).hostname
    logging.debug(f"Hostname of {url} is {hostname}")
    logging.debug("Attempting to get running queues...")
    running_queues = get_consumer_queues(url, get_ip_addresses(hostname))
    logging.debug(f"Running queues are retrieved: {running_queues}")

    print(f"Queues from the services:\n{service_queues}\n{service_names}")
    print(f"Running queues:\n{running_queues}")

    queues_not_found = []
    result = True

    for index, queue in enumerate(service_queues):
        if queue not in running_queues:
            message = f"Queue {queue} was not found!"
            logging.warning(message)
            print(message)

            queues_not_found.append(service_names[index])
            result = False
        else:
            message = f"Queue {queue} was found."
            logging.debug(message)
            print(message)

    if result:
        message = "Success! Everything's working successfully"
        logging.debug(message)
        print(message)
    else:
        message = "There are services that need to restarted"
        logging.error(message)
        print(message)

    if queues_not_found:
        log_message = f"Services that need to be restarted {queues_not_found}"
        logging.error(log_message)
        if not arguments.do_not_send_slack_message:
            send_slack_message(log_message)
        print(log_message)

    return queues_not_found


def is_valid_pid_file(pid_file):
    pid_file_path = "/home/dopigo/celery"  # TODO: This should be moved to the evnironment variable
    full_path = os.path.join(pid_file_path, pid_file)
    if os.path.exists(full_path) and os.path.isfile(full_path):
        return True
    return False


def get_pid_file_of_service(service_file):
    pid_file = "File name is not parsed, yet!"
    full_path = os.path.join(service_file_path, service_file)
    logging.debug(f"Opening {service_file} to get pid of the file")
    with open(full_path, 'r') as file:
        lines = file.readlines()
        lines = [line.rstrip("\n") for line in lines]  # get rid of new line at the end
        for line in lines:
            if line.startswith("ExecStart"):
                exec_start_line = line.split(" ")
                contains_pid_file = [arg for arg in exec_start_line if arg.startswith("--pid")]
                logging.debug(f"The pid file is found.")
                pid_file = contains_pid_file[0].split("=")[1]
                pid_file.replace("%n", service_file)
                if is_valid_pid_file(pid_file):
                    return pid_file

    logging.debug(f"pid file could not found for <{pid_file}>")
    return None


def get_server_ip():
    hostname = get_hostname()
    return str(set(get_ip_addresses(hostname)))


def get_server_name():
    result = subprocess.run(["hostname"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        return "Server name could not retrieved."
    else:
        return result.stdout.decode("utf-8").rstrip()


def restart_services(services):
    for service in services:
        # try to stop the service even if it is dead
        logging.debug(f"Attempting to stop the service {service}")
        result = subprocess.run(["systemctl", "stop", service])
        logging.debug(f"{service} is stopped with the status code of {result.returncode}")

        # find the pid file
        logging.debug(f"Attempting to get pid file of {service}")
        try:
            pid_file = get_pid_file_of_service(service)
        except IndexError:
            pid_file = None
        logging.debug(f"The pid of {service} is retrieved: {pid_file}")

        # delete obsolete pid file
        if pid_file:
            logging.debug(f"Attempting to remove the pid file")
            result = subprocess.run(["rm", pid_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode:
                logging.error(f"Something went wrong when removing {pid_file}. Response: {result.stdout}")

        # raises uo the services
        logging.debug(f"Attempting to restart the service {service}")
        result = subprocess.run(["systemctl", "restart", service])
        logging.debug(f"{service} is restarted with the status code of {result.returncode}")
        if not result.returncode:
            message = f"{get_server_name()}:{get_server_ip()} {service} is restarted."
            logging.debug(message)
            print(message)
        else:
            message = f"{get_server_name()}:{get_server_ip()} {service} service needs to be restarted but could not."
            logging.error(message)
            print(message)

        if not arguments.do_not_send_slack_message:
            send_slack_message(message)


def get_slack_token():
    try:
        return environ["DOPIGO_SLACK_TOKEN"]
    except KeyError:
        error_message = "DOPIGO_SLACK_TOKEN is not set."
        logging.error(error_message)
        raise KeyError(error_message)


def send_slack_message(message):
    logging.debug("Attempting to retrieve DOPIGO_SLACK_TOKEN")
    slack_token = get_slack_token()
    logging.debug("DOPIGO_SLACK_TOKEN is retrieved.")
    client = WebClient(token=slack_token)

    try:
        logging.debug("Sending message to Slack.")
        response = client.chat_postMessage(
            channel="#worker-alarms",
            text=message,
        )
        if response.status_code < 300:
            logging.debug("Message is successfully sent.")
        else:
            logging.debug(f"Message could not sent. (HTTP {response.status_code})")
    except SlackApiError as e:
        logging.error(f"Something went wrong when sending message to Slack. Response: {e}")


def main():
    try:
        restart_services(check_queues())
    except Exception as e:
        msg = f"An error occurred in {get_server_name()}:{get_server_ip()}: {e}"
        print(msg)
        if not arguments.do_not_send_slack_message:
            send_slack_message(msg)


if __name__ == '__main__':
    main()
