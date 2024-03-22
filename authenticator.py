#!/usr/bin/env python3

import sys
import os
from glob import glob
from subprocess import check_output, CalledProcessError
from cryptography.fernet import Fernet
import requests
import subprocess

uri = sys.argv[1]
print("URI:", uri)
id = uri.split("=")[1]
print(f" id is: {id}")

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode()

def get_usb_devices():
    sdb_devices = map(os.path.realpath, glob('/sys/block/sd*'))
    usb_devices = (dev for dev in sdb_devices
        if 'usb' in dev.split('/')[5])
    return dict((os.path.basename(dev), dev) for dev in usb_devices)

def get_mount_points():
    try:
        output = subprocess.check_output(['wmic', 'logicaldisk', 'get', 'caption']).decode('utf-8')
        lines = output.strip().split('\n')[1:]
        return [(line.strip(), f"{line.strip()}\\") for line in lines]
    except subprocess.CalledProcessError:
        return []


if __name__ == '__main__':
    paths = get_mount_points()


    for i, (drive_letters, drive_path) in enumerate(paths):
        print(f"({drive_letters}, {drive_path}) -- press{i}")
    path_select = int(input("Enter any:_"))

    selected_drive_letter,selected_drive_path = paths[path_select]
    file_path = ""

    count = 0
    while file_path == "":

        if count == 50:
            response = requests.post("http://127.0.0.1:8000/user/physical-key-authentication/",data={'unique_id': id,'authentication':'fail'})
            break
        
        for path in paths:
            # Check whether the specified
            # path exists or not
            if path[1] == selected_drive_path:
                isExist = os.path.exists(path[1]+"/key.txt")
                file_path = path[1]+"/key.txt"
            else:
                isExist = os.path.exists(path[1]+"/key.txt")

            if isExist == True:
                print("Key found, decrypting...")
                with open(file_path) as f:
                    data  = f.readlines()

                    key = data[0].split("\n")[0]

                    encrypted_data = data[1].split("\n")[0]

                    encrypted_data = bytes(encrypted_data,'utf-8')
                    
                    decrypted_data = decrypt_data(encrypted_data, key)

                    print(f"decrypted_data is {decrypted_data}")

                    if decrypted_data == id:
                        print("Physical Key Authenticated")
                        response = requests.post("http://127.0.0.1:8000/user/physical-key-authentication/",data={'unique_id': id,'authentication':'success'})
                    else:
                        print("Physical Key Authentication failed")
                        response = requests.post("http://127.0.0.1:8000/user/physical-key-authentication/",data={'unique_id': id,'authentication':'fail'})
            else:
                print("Keys not found")

        count+= 1

    

    



