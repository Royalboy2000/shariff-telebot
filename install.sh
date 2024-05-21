#!/bin/bash

sudo apt-get update
sudo apt-get upgrade -y

sudo apt-get install -y python3 python3-pip

pip3 install telebot instagrapi pyfiglet colorama

sudo apt-get install -y nmap

sudo apt-get install -y gobuster

sudo apt-get install -y ruby-full
sudo gem install wpscan

sudo apt-get install -y masscan

git clone https://github.com/sherlock-project/sherlock.git
cd sherlock
pip3 install -r requirements.txt
cd ..

sudo ln -s $(pwd)/sherlock/sherlock.py /usr/local/bin/sherlock
