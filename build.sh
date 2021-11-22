#!/bin/bash

# if the APP_NAME is going to change, cd into /etc/systemd/system and
# change the ExecStart option in celery_worker_monitor.service
APP_NAME="app.py"
SERVICE="celery_worker_monitor"
SERVICE_NAME="celery_worker_monitor.service"
VIRTUAL_ENV_NAME="celery_venv"

git clone https://github.com/Dopigo/CeleryWorkerMonitor.git && cd CeleryWorkerMonitor

echo "Creating virtual environment..."
python3 -m venv ${VIRTUAL_ENV_NAME}

echo "Activating virtual environment..."
source ${VIRTUAL_ENV_NAME}/bin/activate

pip install -r requirements.txt

echo "Converting the python script to a binary..."
chmod +x ${APP_NAME}
mv -i ${APP_NAME} /usr/bin

echo "Handling minor details..."
chmod 644 ${SERVICE_NAME}
mv -i ${SERVICE_NAME} /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE}

echo "Starting ${SERVICE_NAME}..."
sudo systemctl start ${SERVICE}

echo "${SERVICE_NAME} is successfully installed."
echo "Run systemctl status ${SERVICE} to check its status."
