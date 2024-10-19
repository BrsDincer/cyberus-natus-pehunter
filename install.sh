#!/bin/bash

if [[ $(id -u) -ne 0 ]]; then 
	echo "YOU NEED TO RUN AS ROOT" 
	exit 1
fi

pehunter_version="0.0.1"

echo "Installation script CYBERUSPEHunter $pehunter_version"

read -rsp $'[INFO] PRESS [ENTER] TO CONTINUE [INFO]\n'

apt -y install python3
apt -y install python3-dev
apt -y install python3-pip
apt -y install libssl-dev
apt -y install libmagic-dev
apt -y install swig

echo -e "\n[INFO] Installing requirements -setup.py [INFO]\n"
python3 setup.py install
