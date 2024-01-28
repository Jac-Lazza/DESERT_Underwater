#!/usr/bin/python3

"""
	One Time Pad application

	Simple script that works as a bridge between the open soruce DESERT framework
	and the closed source QKD project for the University of Padua.
	Simply put, the scripts gets a random key from a QKD network and then uses a
	Vernam cipher (also known as One Time Pad) for encrypting the data to send.
	A ciphered checksum is used as digital signature for checking each packet
	integrity.
	
	This script is only intended for experimental and demonstration purposes.
"""

import sys
import json
import socket
import time
import random

### CONSTANTS ###

APP_MODE_TX = "TX"
APP_MODE_RX = "RX"

TX_NUMBER = 300 #Number of transmissions to perform/expect

PAYLOAD_SIZE = 20
# KEYRING_ID_SIZE = 2
KEY_INDEX_SIZE = 2
CHECKSUM_SIZE = 2

# HEADER_SIZE = KEYRING_ID_SIZE + KEY_INDEX_SIZE
PACKET_SIZE = KEY_INDEX_SIZE + PAYLOAD_SIZE + CHECKSUM_SIZE
KEY_SIZE = PAYLOAD_SIZE + CHECKSUM_SIZE

# KEYRING = {} #Where all the OTPs are going to be stored
SECRET_KEY = b""

### ~~~ ###

### Utility functions ###

def xor_payload(payload : bytes, key_index : int) -> bytes:
	"""
		Encrypts or decrypts the whole payload using a portion of the OTP 
		identified by key_index.
		If the key_index can't be used to retrieve a valid portion of the OTP
		an empty bytestring is retrieved instead.

		This function requires that the length of the payload is equal to
		the length of the key used, where with key we refer to the portion
		of the OTP used.
	"""

	assert(len(payload) == KEY_SIZE)

	# if(not keyring_id in KEYRING.keys()):
	# 	return None

	# otp_key = KEYRING[keyring_id][key_index*KEY_SIZE : (key_index+1)*KEY_SIZE]
	otp_key = SECRET_KEY[key_index*KEY_SIZE : (key_index+1)*KEY_SIZE]
	if(len(otp_key) != KEY_SIZE):
		return None #We reached the end of the OTP key, further secure communication is not possible
	
	result = b""
	for x,y in zip(payload, otp_key):
		result += (x^y).to_bytes(length=1, byteorder="big")
	return result

def checksum(data : bytes) -> bytes:
	"""
		Implements the standard IP checksum described by
		Jon Postel in RFC 791
	"""

	total = 0

	for i in range(0, len(data), 2):
		total += int.from_bytes(data[i : i+2], byteorder="big")
		if(total >= 0x010000):
			total += 1
			total &= 0xFFFF
	
	total = 0xFFFF - total

	return total.to_bytes(length=2, byteorder="big")

def print_log(logfile, line : str):
	"""
		Prints to standard output and writes
		to logfile

		logfile is a valid file descriptor wrapper
	"""

	print(line)
	logfile.write(line + "\n")
	logfile.flush()


### ~~~ ###

### QKD interface helper functions ###

def __init_qkd_request(command : str) -> dict:
	"""
		Returns a request template valid for any call
		to the QKD keymanager API.

		This function should only be used by qkd_* functions.
	"""

	request_template = {}
	request_template["command"] = command
	request_template["parameters"] = {}
	request_template["continues"] = "no"
	return request_template

def __send_request(qkd_socket : socket.socket, request : dict):
	"""
		Sends a request to the QKD keymanager entity.
		
		The data to be sent is serialized in such a way
		that it is understandable by the Qt socket on the other end.
		
		The serialization is simple: add 4 bytes that indicates the size
		of the next bytestring that is going to be sent.

		This function should only be used by qkd_* functions. 
	"""

	request = json.dumps(request).encode()
	request = len(request).to_bytes(length=4, byteorder="big") + request
	qkd_socket.sendall(request)

def __recv_response(qkd_socket : socket.socket, raw : bool = False):
	"""
		Waits and returns a response from the QKD keymanager entity.

		The data is serialized in such a way that it is understandable
		by the Qt socket on the other end. Refer to __send_request documentation
		for details on the serialization.

		If the raw flag is False then the data received is interpreted as a JSON,
		otherwise the bytestring is returned as is (this is useful when receiving
		a key).

		Note: The HEARTBEAT string is sent by the QKD keymanager to keep alive
		the connection. It can happen that between a request and a response such
		string is read instead.
		Since I cannot modify this behaviour of the keymanager, whenever the HEARBEAT
		string is read, it is immediately discarded.

		This function should only be used by qkd_* functions.
	"""

	while(True):
		size = qkd_socket.recv(4)
		size = int.from_bytes(size, byteorder="big")
		
		# response = qkd_socket.recv(size)
		response = b""
		while(len(response) < size):
			response += qkd_socket.recv(size - len(response))
		
		if(response != b"HEARTBEAT"):
			break
	if(not raw):
		return json.loads(response.decode())
	else:
		return response

### QKD keymanager API ###

def qkd_connect(qkd_socket : socket.socket, source : str, destination : str, sessionid : str, qos : dict = {}) -> bool:
	"""
		Creates a connection between source and destination. A sessionid is provided a priori 
		so that the QKD keymanager will not generate its own.

		qkd_socket is connected to the QKD keymanager.
		source and destination must be valid node names of the QKD entities.
		sessionid must be a UUID
	"""

	request = __init_qkd_request("QKDOPEN")

	request["parameters"]["SOURCE"] = source
	request["parameters"]["DESTINATION"] = destination
	request["parameters"]["QOS"] = qos
	request["parameters"]["SESSIONID"] = sessionid

	__send_request(qkd_socket, request)
	response = __recv_response(qkd_socket)

	return response["parameters"]["STATUS"] == "0"
	

def qkd_get_status(qkd_socket : socket.socket, destination : str) -> dict:
	"""
		Returns the status of the QKD node named destination.

		qkd_socket is connected to the QKD manager.
		destination must be a valid node name of the QKD entity.
	"""

	request = __init_qkd_request("QKDGETSTATUS")

	request["parameters"]["DESTINATION"] = destination

	__send_request(qkd_socket, request)
	response = __recv_response(qkd_socket)

	return response

def qkd_get_key(qkd_socket : socket.socket, sessionid : str, index : str = "", meta : str = "") -> bytes:
	"""
		Returns a random key from the QKD network.
		If no key is avaiable then None is returned.

		sessionid must be a UUID of a valid connection between two QKD nodes.
	"""

	request = __init_qkd_request("QKDGETKEY")

	request["parameters"]["SESSIONID"] = sessionid
	request["parameters"]["INDEX"] = index
	request["parameters"]["META"] = meta

	__send_request(qkd_socket, request)
	response = __recv_response(qkd_socket)

	if(response["parameters"]["STATUS"] == "0"):
		#This means that the next transmission is going to be a key
		return __recv_response(qkd_socket, True)

def qkd_close(qkd_socket : socket.socket, sessionid : str) -> bool:
	"""
		Closes the connection between two QKD nodes.

		sessionid must be a UUID of a valid connection between two QKD nodes.
	"""

	request = __init_qkd_request("QKDCLOSE")

	request["parameters"]["SESSIONID"] = sessionid

	__send_request(qkd_socket, request)
	response = __recv_response(qkd_socket)

	return response["parameters"]["STATUS"] == "0"

### ~~~ ###


if __name__ == "__main__":
	### CLI-argument parsing
	if(len(sys.argv) -1 != 4):
		print("Usage: python3 OTP_app.py TX|RX config.json log_filename key_file")
		sys.exit(1)
	
	#Managing transmissions modes: TX or RX
	app_mode = sys.argv[1].upper()
	if((app_mode != APP_MODE_RX) and (app_mode != APP_MODE_TX)):
		print("Avaiables app modes: TX or RX")
		sys.exit(1)
	
	#Reading and parsing configuration file
	print("Reading configuration file: " + sys.argv[2])
	with open(sys.argv[2], "r") as file:
		content = file.read()
	config = json.loads(content)

	desert_address = (config["DESERT"]["address"], config["DESERT"]["port"])
	qkd_address = (config["QKD"]["address"], config["QKD"]["port"])
	qkd_node_local = config["QKD"]["name"]
	node = config["QKD"]["node"]
	OTP_size = config["key_size"]

	#Opening log_file
	log_file = open(sys.argv[3], "x")

	#Managing key file
	secret_key_filename = sys.argv[4]
	try:
		key_file = open(secret_key_filename, "xb")
		perform_qkd_exchange = True
	except:
		key_file = open(secret_key_filename, "rb")
		perform_qkd_exchange = False

	### QKD keymanager connection
	if(perform_qkd_exchange):
		qkd_node_remote = node["name"]
		session_id = node["session_id"]
		input("Press ENTER to start key exchange")

		print("Connection to QKD keymanager entity: ", qkd_address)
		qkd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
		qkd_socket.connect(qkd_address)

		if(not qkd_connect(qkd_socket, qkd_node_local, qkd_node_remote, session_id)):
			print("[ERROR] Connection to the QKD network failed")
			exit(1)
		
		#Synchronization time, must not be >= than 9
		#Otherwise the connection with the QKD keymanager is interrupted.
		#This behaviour is programmed into the QKD keymanager for the moment.
		#This script can only adapt to it.
		time.sleep(5)

		SECRET_KEY = b""
		while(len(SECRET_KEY) < OTP_size):
			secret = qkd_get_key(qkd_socket, session_id)
			if(secret == None):
				print("[ERROR] Not enough bits for building secret key")
				exit(1)
			SECRET_KEY += secret
		
		# if(not qkd_close(qkd_socket, session_id)):
		# 	print("[WARNING] Problems in closing the connection with QKD network")
		
		qkd_socket.close()
		print_log(log_file, "Key exchange done! [{} B]".format(len(SECRET_KEY)))
		
		key_file.write(SECRET_KEY)
		key_file.close()
		print_log(log_file, "OTP key written to: " + secret_key_filename)
	else:
		print_log(log_file, "Reading OTP key from: " + secret_key_filename)
		SECRET_KEY = key_file.read()
		key_file.close()
		print_log(log_file, "Read [{} B]".format(len(SECRET_KEY)))
	
	input("Press ENTER to start " + app_mode)
	

	### DESERT connection
	print("Connection to the DESERT framework: ", desert_address)
	desert_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	desert_socket.connect(desert_address)

	start_time = time.time()
	print_log(log_file, "{} begins {}".format(time.ctime(), app_mode))

	if(app_mode == APP_MODE_TX):
		key_index = 0
		while(key_index < TX_NUMBER):
			payload = (key_index%256).to_bytes(length=1, byteorder="big")*PAYLOAD_SIZE

			key_index_header = key_index.to_bytes(length=KEY_INDEX_SIZE, byteorder="big")
			chk_trailer = checksum(key_index_header + payload)

			ciphered_payload = xor_payload(payload + chk_trailer, key_index)
			if(ciphered_payload == None):
				print("[ERROR] OTP key size is insufficient")
				sys.exit(1)

			print_log(log_file, "[{}] Sending packet {}: {}".format(time.strftime("%X"), key_index, payload))
			# print("DEBUG: ", ciphered_payload)

			#To check the correctness of the digital signature
			#every now and then the header of a packet gets corrupted
			#the receiver should be able to detect the corruption and
			#should discard the packet
			if(random.randint(1,10) == 10):
				# key_index_header = b"\x00\x00"
				key_index_header = (key_index+1).to_bytes(length=KEY_INDEX_SIZE, byteorder="big")
				print_log(log_file, "Packet {} is compromised".format(key_index))
			###

			desert_socket.sendall(key_index_header + ciphered_payload)
			key_index += 1
			#Does DESERT have a problem if we send data too fast?
			time.sleep(5)

	else: #app_mode == APP_MODE_RX
		pkt_counter = 0
		while(pkt_counter < TX_NUMBER):
			data = b""
			while(len(data) < PACKET_SIZE):
				d = desert_socket.recv(PACKET_SIZE - len(data))
				if(d == b""):
					data = b""
					break #From the inner loop
				data += d
			
			if(data == b""):
				break #End of RX
			
			# print("DEBUG: ", data)
			
			key_index = int.from_bytes(data[:KEY_INDEX_SIZE], byteorder="big")
			content = xor_payload(data[KEY_INDEX_SIZE:], key_index)
			if(content == None):
				# print("[ERROR] OTP key size is insufficient") #Doesn't make sense for the receiver
				# sys.exit(1)
				print_log(log_file, "[{}] Packet received, but key_index is too large! => Packet is not valid".format(time.strftime("%X")))
				pkt_counter += 1
				continue

			payload = content[:-CHECKSUM_SIZE]


			recv_chk = content[-CHECKSUM_SIZE:]
			cmp_chk = checksum(data[:KEY_INDEX_SIZE] + payload)
			if(recv_chk == cmp_chk):
				print_log(log_file, "[{}] Packet received {}: {}".format(time.strftime("%X"), key_index, payload))
			else:
				print_log(log_file, "[{}] Packet received, but checksum failed!".format(time.strftime("%X")))
			pkt_counter += 1 #We also count packets with failed checksum
		
		print_log(log_file, "Packets received: {}/{} ({}%)".format(pkt_counter, TX_NUMBER, pkt_counter/TX_NUMBER*100))


	end_time = time.time()
	print_log(log_file, "{} ends {}".format(time.ctime(), app_mode))

	total_time = end_time - start_time
	print_log(log_file, "~~~~~~ Elapsed time: {} seconds ~~~~~~".format(total_time))

	desert_socket.close()
	log_file.close()

