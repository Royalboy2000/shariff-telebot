import subprocess
import telebot
from telebot import types
import tempfile
import os


TOKEN = 'telegram bot token'

# Create an instance of the Bot
bot = telebot.TeleBot(TOKEN)

@bot.message_handler(commands=['start'])
def handle_start(message):
    photo_path = '/home/samir/Downloads/51e043a6-0657-4529-b9e8-4a4914a22b15.png'
    with open(photo_path, 'rb') as photo:
        bot.send_photo(message.chat.id, photo)
    bot.send_message(message.chat.id, "Welcome to CodeBreakers Bot! \n you can use use /nmap\n /nikto  \n /wpscan coming soon... \n you can use /searchsploit (name) \n example:/searchsploit smb")

@bot.message_handler(commands=['nmap'])
def handler_nmap(message):
    bot.send_message(message.chat.id, "WHATS THE TARGET IP? : ")
    
    bot.register_next_step_handler(message, lambda m: handle_nmap_target(m))

def handle_nmap_target(message):
    user_id = message.from_user.id
    target = message.text.strip()

    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, one_time_keyboard=True)
    quick_button = types.KeyboardButton("Quick Scan")
    medium_button = types.KeyboardButton("Medium Scan")
    vulnerable_button = types.KeyboardButton("Vulnerable Scan")
    service_button = types.KeyboardButton("service scan ")
    markup.add(quick_button, medium_button, vulnerable_button, service_button)

    bot.send_message(user_id, f" Please select the type of Nmap scan you want to run:", reply_markup=markup)
    bot.register_next_step_handler(message, lambda m: handle_nmap_type(m, target))


def handle_nmap_type(message, target):
    user_id = message.from_user.id
    user_input = message.text.lower()

    if user_input in ['quick scan', 'medium scan', 'vulnerable scan']:
        scan_options = {
            "quick scan": "-T4 -F",
            "medium scan": "-T4 -A",
            "vulnerable scan": "-T4 --script vuln"
        }
        nmap_command = f"nmap {scan_options[user_input]} {target}"
        bot.send_message(user_id, f"Executing Nmap {user_input} for target: {target}")
        execute_command(user_id, nmap_command)
    else:
        bot.send_message(user_id, "Please select a valid option: Quick Scan, Medium Scan, or Vulnerable Scan.")

@bot.message_handler(commands=['searchsploit'])
def handle_searchsploit(message):
    user_id = message.from_user.id
    command = message.text.strip()
    keyword = command.replace('/searchsploit', '').strip()
    bot.send_message(user_id, f"Searching for exploits with keyword: {keyword}")
    execute_command(user_id, f"searchsploit '{keyword}'")

@bot.message_handler(commands=['wpscan'])
def handle_wpscan(message):
    bot.send_message(message.chat.id, "Please enter the target (e.g., example.com): ")
    bot.register_next_step_handler(message, lambda m: handle_wpscan_target(m))

def handle_wpscan_target(message):
    user_id = message.from_user.id
    target = message.text.strip()

    bot.send_message(message.chat.id, "whats your wpscan api token? : ")

    bot.register_next_step_handler(message, lambda m: handle_wpscan_token(m, target))

def handle_wpscan_token(message,target):
    user_id = message.from_user.id
    token = message.text.strip()  

    wpscan_command = f"wpscan --url {target} --api-token {token}"
    bot.send_message(user_id, f"Executing wpscan for target: {target} and api token {token}")
    execute_command(user_id, wpscan_command)

@bot.message_handler(commands=['nikto'])
def handle_nikto(message):
    bot.send_message(message.chat.id, "please enter your target: ")
    bot.register_next_step_handler(message, lambda m: handle_nikto_target(m))
    
def handle_nikto_target(message):
    user_id = message.from_user.id
    nikto_target = message.text.strip()

    nikto_command = f"nikto -h {nikto_target}"
    bot.send_message(user_id, f"Executing nikto for target: {nikto_target}")
    execute_command(user_id, wpscan_command)



@bot.message_handler()
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

if __name__ == "__main__":
    bot.polling(timeout=30)
