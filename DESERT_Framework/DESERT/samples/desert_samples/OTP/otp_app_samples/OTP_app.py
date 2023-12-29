#!/usr/bin/python3

"""
Author: Jacopo Lazzarin
Version: 1.0
Simple script that works as a bridge between the open soruce DESERT framework
and the closed source QKD project for the University of Padua.
Simply put, the scripts gets a random key from a QKD network and then uses a
Vernam cipher (also known as One Time Pad) for encrypting the data to send.
At the moment it supports just one simplex connection.
This script is intended for experimental and demonstration purposes.
"""

import sys
import json
import socket
import time
import random

### CONSTANTS ###

APP_MODE_TX = "TX"
APP_MODE_RX = "RX"

PAYLOAD_SIZE = 30
KEYRING_ID_SIZE = 2
KEY_INDEX_SIZE = 2
HEADER_SIZE = KEYRING_ID_SIZE + KEY_INDEX_SIZE
PACKET_SIZE = HEADER_SIZE + PAYLOAD_SIZE

KEYRING = {}

### ~~~ ###

### Utility functions ###

def xor_payload(payload : bytes, keyring_id : int,key_index : int) -> bytes: #TODO update this function
	assert(len(payload) == PAYLOAD_SIZE)

	if(not keyring_id in KEYRING.keys()):
		return None

	otp_key = KEYRING[keyring_id][key_index*PAYLOAD_SIZE : (key_index+1)*PAYLOAD_SIZE]
	result = b""
	for x,y in zip(payload, otp_key):
		result += (x^y).to_bytes()
	return result

### ~~~ ###

### QKD interface functions ###

def __init_qkd_request(command : str) -> dict:
	request_template = {}
	request_template["command"] = command
	request_template["parameters"] = {}
	request_template["continues"] = "no"
	return request_template

def __send_request(qkd_socket : socket.socket, request : dict):
	request = json.dumps(request).encode()
	request = len(request).to_bytes(length=4) + request
	qkd_socket.send(request)

def __recv_response(qkd_socket : socket.socket, raw : bool = False) -> dict:
	while(True):
		size = qkd_socket.recv(4)
		size = int.from_bytes(size)
		response = qkd_socket.recv(size)
		# print("DEBUG size: ", size)
		# print("DEBUG response: ", response)
		if(response != b"HEARTBEAT"):
			break
	if(not raw):
		return json.loads(response.decode())
	else:
		return response

def qkd_connect(qkd_socket : socket.socket, source : str, destination : str, sessionid : str, qos : dict = {}) -> bool:
	request = __init_qkd_request("QKDOPEN")

	request["parameters"]["SOURCE"] = source
	request["parameters"]["DESTINATION"] = destination
	request["parameters"]["QOS"] = qos
	request["parameters"]["SESSIONID"] = sessionid

	__send_request(qkd_socket, request)
	response = __recv_response(qkd_socket)

	return response["parameters"]["STATUS"] == "0"
	

def qkd_get_status(qkd_socket : socket.socket, destination : str):
	request = __init_qkd_request("QKDGETSTATUS")

	request["parameters"]["DESTINATION"] = destination

	__send_request(qkd_socket, request)
	response = __recv_response(qkd_socket)

	return response

def qkd_get_key(qkd_socket : socket.socket, sessionid : str, index : str = "", meta : str = ""):
	request = __init_qkd_request("QKDGETKEY")

	request["parameters"]["SESSIONID"] = sessionid
	request["parameters"]["INDEX"] = index
	request["parameters"]["META"] = meta

	__send_request(qkd_socket, request)
	response = __recv_response(qkd_socket)

	if(response["parameters"]["STATUS"] == "0"):
		#This means that the next transmission is going to be a key
		return __recv_response(qkd_socket, True)

def qkd_close(qkd_socket : socket.socket, sessionid : str):
	request = __init_qkd_request("QKDCLOSE")

	request["parameters"]["SESSIONID"] = sessionid

	__send_request(qkd_socket, request)
	response = __recv_response(qkd_socket)

	return response["parameters"]["STATUS"] == "0"

### ~~~ ###


if __name__ == "__main__":
	### CLI-argument parsing
	if(len(sys.argv) -1 != 2): #Maybe make filename optional
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
		
		time.sleep(5) #Syncronization time, must not be >= than 9

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
			
			encr_payload = xor_payload(payload, k_id, key_indexes[k_id])
			
			keyring_id_header = k_id.to_bytes(length=KEYRING_ID_SIZE)
			key_index_header = key_indexes[k_id].to_bytes(length=KEY_INDEX_SIZE)
			desert_socket.send(keyring_id_header + key_index_header + encr_payload)

			key_indexes[k_id] += 1
			time.sleep(1)
		
	else: #app_mode == APP_MODE_RX
		while(True):
			data = desert_socket.recv(PACKET_SIZE)
			if(data == b""):
				print("RX done!")
				break
			assert(len(data) == PACKET_SIZE)

			k_id = int.from_bytes(data[:KEYRING_ID_SIZE])
			key_index = int.from_bytes(data[KEYRING_ID_SIZE : HEADER_SIZE])
			payload = xor_payload(data[HEADER_SIZE:], k_id, key_index)
			if(payload != None):
				print("[{}] Received: {}".format(k_id, payload))
	
	#Releasing DESERT resources
	desert_socket.close()

