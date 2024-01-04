#!/usr/bin/python3

"""
	One Time Pad application

	Simple script that works as a bridge between the open soruce DESERT framework
	and the closed source QKD project for the University of Padua.
	Simply put, the scripts gets a random key from a QKD network and then uses a
	Vernam cipher (also known as One Time Pad) for encrypting the data to send.
	
	At the moment it can support multiple simplex connections.
	Also, a ciphered checksum is used as a digital signature for checking each
	packet integrity.
	
	This script is only intended for experimental and demonstration purposes.

	Author: Jacopo Lazzarin
"""

import sys
import json
import socket
import time
import random

### CONSTANTS ###

APP_MODE_TX = "TX"
APP_MODE_RX = "RX"

PAYLOAD_SIZE = 20
KEYRING_ID_SIZE = 2
KEY_INDEX_SIZE = 2
CHECKSUM_SIZE = 2

HEADER_SIZE = KEYRING_ID_SIZE + KEY_INDEX_SIZE
PACKET_SIZE = HEADER_SIZE + PAYLOAD_SIZE + CHECKSUM_SIZE
KEY_SIZE = PAYLOAD_SIZE + CHECKSUM_SIZE

KEYRING = {} #Where all the OTPs are going to be stored

### ~~~ ###

### Utility functions ###

def xor_payload(payload : bytes, keyring_id : int, key_index : int) -> bytes:
	"""
		Encrypts or decrypts the whole payload using a portion of the OTP 
		identified by keyring_id. The key_index parameter is used to select 
		the correct portion of the OTP to use.

		This function requires that the length of the payload is equal to
		the length of the key used, where with key we refer to the portion
		of the OTP used.
	"""

	assert(len(payload) == KEY_SIZE)

	if(not keyring_id in KEYRING.keys()):
		return None

	otp_key = KEYRING[keyring_id][key_index*KEY_SIZE : (key_index+1)*KEY_SIZE]
	result = b""
	for x,y in zip(payload, otp_key):
		result += (x^y).to_bytes()
	return result

def checksum(data : bytes) -> bytes:
	"""
		Implements the standard IP checksum described by
		Jon Postel in RFC 791
	"""

	total = 0

	for i in range(0, len(data), 2):
		total += int.from_bytes(data[i : i+2])
		if(total >= 0x010000):
			total += 1
			total &= 0xFFFF
	
	total = 0xFFFF - total

	return total.to_bytes(length=2)
	


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
	request = len(request).to_bytes(length=4) + request
	qkd_socket.send(request)

def __recv_response(qkd_socket : socket.socket, raw : bool = False):
	"""
		Waits and returns a response from the QKD keymanager entity.

		The data is serialized in such a wai that it is understandable
		by the Qt socket on the other end. Refer to __send_request documentation
		for details on the serialization.

		If the raw flag is False then the data received is interpreted as a JSON,
		otherwise the bytestring is returned as is (this is useful when receiving
		a key).

		Note: The HEARTBEAT string is sent by the QKD keymanager to keep alive
		the connection. It can happen that between a request and a response such
		string is read instead.
		Since I cannot modify this behaviour of the keymanager, whenever the HEARBEAT
		string is read it is immediately discarded.

		This function should only be used by qkd_* functions.
	"""

	while(True):
		size = qkd_socket.recv(4)
		size = int.from_bytes(size)
		response = qkd_socket.recv(size)
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
	if(len(sys.argv) -1 != 2):
		print("Usage: python3 OTP_app.py TX|RX config.json")
		sys.exit(1)
	
	app_mode = sys.argv[1].upper()
	if((app_mode != APP_MODE_RX) and (app_mode != APP_MODE_TX)):
		print("Avaiables app modes: TX or RX")
		sys.exit(1)
	
	print("Reading configuration file: " + sys.argv[2])
	with open(sys.argv[2], "r") as file:
		content = file.read()
	config = json.loads(content)

	desert_address = (config["DESERT"]["address"], config["DESERT"]["port"])
	qkd_address = (config["QKD"]["address"], config["QKD"]["port"])
	qkd_node_local = config["QKD"]["name"]
	nodes = config["QKD"]["nodes"]
	key_size = config["key_size"]

	### QKD keymanager connection
	for n in nodes:
		qkd_node_remote = n["name"]
		session_id = n["session_id"]
		keyring_id = n["keyring_id"]

		print("[READY] uuid: " + session_id)
		input("Press ENTER to start key exchange")

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

		if(keyring_id in KEYRING.keys()):
			print("[ERROR] keyring id already in use!")
			exit(1)
		secret_key = b""
		while(len(secret_key) < key_size):
			piece = qkd_get_key(qkd_socket, session_id)
			if(piece == None):
				print("[ERROR] Not enough bits for building secret key")
				exit(1)
			secret_key += piece
		KEYRING[keyring_id] = secret_key

		if(not qkd_close(qkd_socket, session_id)):
			print("[WARNING] Problems in closing the connection with QKD network")
		
		qkd_socket.close()
		print("Key exchange done!")
	
	print("Key setup finished!")
	input("Press ENTER to start " + app_mode)

	### DESERT connection
	print("Connecting to the DESERT framework: ", desert_address)
	desert_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	desert_socket.connect(desert_address)

	if(app_mode == APP_MODE_TX):
		key_indexes = {}
		for k_id in KEYRING.keys():
			key_indexes[k_id] = 0

		while(True):
			k_id = random.choice(list(KEYRING.keys()))
			payload = ((key_indexes[k_id]+1)%256).to_bytes(length=1)*PAYLOAD_SIZE
			print("[{}] Sending: {}".format(k_id, payload))
			
			keyring_id_header = k_id.to_bytes(length=KEYRING_ID_SIZE)
			key_index_header = key_indexes[k_id].to_bytes(length=KEY_INDEX_SIZE)
			chk_trailer = checksum(keyring_id_header + key_index_header + payload)

			encr_payload = xor_payload(payload + chk_trailer, k_id, key_indexes[k_id])

			#To check the correctness of the digital signature
			#every now and then the header of a packet gets corrupted
			#the received should be able to detect the corruption and
			#should discard the packet
			if(random.randint(1,10) == 10):
				key_index_header = b"\x00\x00"
				print("Packet is compromised")
			###

			desert_socket.send(keyring_id_header + key_index_header + encr_payload)

			key_indexes[k_id] += 1
			#TODO: Does DESERT have problems if we send data too fast? Configure this waiting time
			time.sleep(5) 
		
	else: #app_mode == APP_MODE_RX
		while(True):
			data = b""
			while(len(data) < PACKET_SIZE):
				part_data = desert_socket.recv(PACKET_SIZE - len(data))
				if(part_data == b""):
					print("RX done!")
					desert_socket.close()
					sys.exit(0)

				data += part_data

			k_id = int.from_bytes(data[:KEYRING_ID_SIZE])
			key_index = int.from_bytes(data[KEYRING_ID_SIZE : HEADER_SIZE])
			
			content = xor_payload(data[HEADER_SIZE:], k_id, key_index)
			if(content != None):
				payload = content[:-CHECKSUM_SIZE]
				
				rcv_chk = content[-CHECKSUM_SIZE:]
				cmp_chk = checksum(data[:HEADER_SIZE] + payload)
				if(rcv_chk == cmp_chk):
					print("[{}] Received: {}".format(k_id, payload))
				else:
					print("Packed failed checksum check!")
	
	#Releasing DESERT resources
	desert_socket.close()

