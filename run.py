try:
	import base64
	import os
	from cryptography.fernet import Fernet
	from cryptography.hazmat.backends import default_backend
	from cryptography.hazmat.primitives import hashes
	from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
	import numpy
	from PIL import Image
	import sys
	import argparse
	import os.path
	from getpass import getpass
	import time
except:
	print("Installing requirements.\n")
	os.system("python3 -m pip install -r requirements.txt")

logo = """\033[1;38m\033[1m
  ____  _   _ ____  _____ _   _  ___   ____ ____      _    ____  _   _ 
 | ___|| | | |  _ \|___ /| \ | |/ _ \ / ___|  _ \    / \  |  _ \| | | |
 |___ \| |_| | |_) | |_ \|  \| | | | | |  _| |_) |  / _ \ | |_) | |_| |
  ___) |  _  |  _ < ___) | |\  | |_| | |_| |  _ <  / ___ \|  __/|  _  |
 |____/|_| |_|_| \_\____/|_| \_|\___/ \____|_| \_\/_/   \_\_|   |_| |_|\033[1;m\033[0m 
                                                 \033[1m\033[37m Made with \033[91m<3\033[37m By 5HR3D\033[1;m\033[0m                      
"""

print(logo)

def slowprint(s):
    for c in s + '\n' :
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(10. / 100)
slowprint("\033[1m\033[1;33m [!] Loading...\n\n\033[1;m\033[0m ")
time.sleep(0)
os.system('clear')

print(logo)

input("\033[1m Enter \033[91mS\033[1;m \033[1mto continue:\033[0m ")
os.system("clear")
print(logo)

print("\n \033[1mOptions:\033[0m \n")
print(" [\033[1;38m01\033[1;m] Encode          [\033[1;38m03\033[1;m] About")
print(" [\033[1;38m02\033[1;m] Decode          [\033[1;38m99\033[1;m] Exit")


choice1 = input(" \n\033[1m\033[1;33m [#]:> \033[1;m\033[0m")

if choice1 == "1" or choice1 == "01":
	print("\n What do you want to Encode?")
	print(" Options:")
	print(" [01] Text")
	print(" [02] File")
	choice2 = input("\033[1m\033[1;33m [#]:> \033[1;m\033[0m")
	if choice2 == "1" or choice2 == "01":
		print("\n Do you want to keep a password? [Y/N] ")
		pas1 = input("\033[1m\033[1;33m [#]:> \033[1;m\033[0m")
		if pas1 == "y" or pas1 == "Y":
			print(" \nEnter text to encode.")
			msg = input (" \033[1m\033[1;33m [#]:> \033[1;m\033[0m")
			pthost = input(" Path to host file: ")
			print("")
			os.system("python3 main.py " + msg + " " + pthost + " -p")
		
		elif pas1 == "N" or pas1 == "n":
			print(" \nEnter text to encode.")
			msg1 = input (" \033[1m\033[1;33m [#]:> \033[1;m\033[0m")
			pthost1 = input(" Path to host file: ")
			print("")
			os.system("python3 main.py " + msg1 + " " + pthost1)	
		else:
			print("Invalid input found. Please re-run the script.")
			
	elif choice2 == "2" or choice2 == "02":
		print(" Do you want to keep a password? [Y/N] ")
		pas2 = input("\033[1m\033[1;33m [#]:> \033[1;m\033[0m")

		if pas2 == "y" or pas2 == "Y":
			victim = input(" Path to file to encode: ")
			host = input(" Path to host file: ")
			print("")
			os.system("python3 main.py " + victim + " " + host + " -p")

		elif pas2 == "N" or pas2 == "n":
			victim1 = input(" Path to file to encode: ")
			host1 = input(" Path to host file: ")
			print("")
			os.system("python3 main.py " + victim1 + " " + host1)

		else:
			print("Invalid input found. Please re-run the script.")

	else:
		print("Invalid input found. Please re-run the script.")


elif choice1 == "2" or choice1 == "02":
	print("\n Does it have a password? [Y/N]")
	askp = input("\033[1m\033[1;33m [#]:> \033[1;m\033[0m")

	if askp == "Y" or askp == "y":
		decode_path = input("\n Path to file to decode: ")
		print("")
		os.system("python3 main.py " + decode_path + " -p")

	elif askp == "n" or askp == "N":
		decode_path1 = input("\n Path to file to decode: ")
		print("")
		os.system("python3 main.py " + decode_path1)
	else:
		print("Invalid input found. Please re-run the script.")

elif choice1 == "3" or choice1 == "03":
	os.system("clear")
	print(logo)
	print("		--> ABOUT <--")
	print("""\n
		Note:
		This Steganography tool was created for educational and personal purposes only. 
		The creators will not be held responsible for any violations of law caused by any
		means by anyone. Please use this tool at your own risk.

		What is steganography?
		Steganography is the practice of concealing a file, message, image, or video within
		another file, message, image, or video. In simple words- hiding media inside media.

		5HR3NOGRAPH (Shre-no-graf) is a steganography tool allowing you to hide text, files,
		images, gifs etc in another Media file.

			There are 2 main files in this directory:

			[01] main.py: The main code; try 'python3 main.py -h'
			[02] run.py: For begginers who are confused.

			>>You can directly use main.py by using arguements, please refer to the documentation to know how.


                This tool was created by: 5HR3D
                           Github: https://github.com/5HR3D
                  	             Mail: its5hr3d@gmail.com

		Goodluck using 5HR3NOGRAPH.
		Thank you.\n""")

elif choice1 == "99":
	exit()

else:
	print("Invalid input found. Please re-run the script.")
