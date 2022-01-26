#!/bin/bash

# if the APP_NAME is going to change, cd into /etc/systemd/system and
# change the ExecStart option in celery_worker_monitor.service
APP_NAME="celery_worker_monitor.py"
SERVICE="worker_monitor"
SERVICE_NAME="worker_monitor.service"
VIRTUAL_ENV_NAME="celery_worker_monitor_venv"

CYAN="\e[96m"
RED="\e[91m"
RESET="\e[0m"

cd /opt
rm -rf CeleryWorkerMonitor
git clone https://github.com/Dopigo/CeleryWorkerMonitor.git && cd CeleryWorkerMonitor

if [ $? -eq 0 ]; then
    echo -e "${CYAN}CeleryWorkerMonitor successfully installed.${RESET}"
else
    echo -e "${RED}An error occured during installation of CeleryWorkerMonitor.
    If there is a directory named CelerWorkerMonitor under /opt, remove it entirely and try again.${RESET}"
    return 1
fi

echo -e "${CYAN}Creating virtual environment...${RESET}"
python3 -m venv ${VIRTUAL_ENV_NAME}

if [ $? -ne 0 ]; then
    echo -e "${RED}Virtual environment could not created!${RESET}"
    return 1
fi

echo -e "${CYAN}Activating virtual environment...${RESET}"
source ${VIRTUAL_ENV_NAME}/bin/activate

if [ $? -ne 0 ]; then
    echo -e "${RED}Virtual environment could not activated!${RESET}"
    return 1
fi
pip install wheel
pip install -r requirements.txt

echo -e "${CYAN}Converting the python script to a binary...${RESET}"
chmod +x ${APP_NAME}
mv -f ${APP_NAME} /usr/bin

echo -e "${CYAN}Handling minor details...${RESET}"
chmod 644 ${SERVICE_NAME}
mv -f ${SERVICE_NAME} /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE}

sudo systemctl stop ${SERVICE} || true
echo -e "${CYAN}Starting ${SERVICE_NAME}...${RESET}"
sudo systemctl start ${SERVICE}

echo -e "${CYAN}${SERVICE_NAME} is successfully installed.${RESET}"
echo -e "${CYAN}Run systemctl status ${SERVICE} to check its status.${RESET}"
