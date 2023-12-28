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

### CONSTANTS ###
SESSION_ID = "00000000-0000-0000-0000-000000000001" #Universal unique identifier for this session

APP_MODE_TX = "TX"
APP_MODE_RX = "RX"

PAYLOAD_SIZE = 30
HEADER_SIZE = 2
PACKET_SIZE = HEADER_SIZE + PAYLOAD_SIZE

SECRET_KEY = b""

### ~~~ ###

### Utility functions ###

def parse_ip_port(data : str) -> (str, int):
	data = data.split(":")
	if(len(data) == 1):
		return ("127.0.0.1", int(data[0]))
	elif(len(data) == 2):
		return (data[0], int(data[1]))
	else:
		raise Exception("Wrong address format")

def xor_payload(payload : bytes, key_index : int) -> bytes:
	assert(len(payload) == PAYLOAD_SIZE)

	otp_key = SECRET_KEY[key_index*PAYLOAD_SIZE : (key_index+1)*PAYLOAD_SIZE]
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
	if(len(sys.argv) -1 != 4):
		print("Usage: python3 OTP_app.py TX|RX DES_IP:DES_PORT QKD_IP:QKD_PORT data_filename")
		sys.exit(1)
	
	app_mode = sys.argv[1].upper()
	if((app_mode != APP_MODE_RX) and (app_mode != APP_MODE_TX)):
		print("Avaiables app modes: TX or RX")
		sys.exit(1)
	
	desert_address = parse_ip_port(sys.argv[2])
	qkd_address = parse_ip_port(sys.argv[3])
	filename = sys.argv[4]

	### QKD keymanager connection
	print("Connecting to the QKD keymanager entity: ", qkd_address)
	qkd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	qkd_socket.connect(qkd_address)

	#################################################
	# qkd_connect(qkd_socket, "1", "2", SESSION_ID) #
	# qkd_get_status(qkd_socket, "2")               #
	# qkd_get_key(qkd_socket, SESSION_ID)           #
	# qkd_close(qkd_socket, SESSION_ID)             #
	#################################################
	
	if(app_mode == APP_MODE_TX):
		qkd_node_local = "alice1"
		qkd_node_remote = "bob"
	else:
		qkd_node_local = "bob"
		qkd_node_remote = "alice1"
	
	if(not qkd_connect(qkd_socket, qkd_node_local, qkd_node_remote, SESSION_ID)):
		print("Error: Connection to the QKD network failed")
		exit(1)
	print("Connection to QKD network established...")
	
	time.sleep(5) #Syncronization time so that everybody connected to the network, not elegant but it works

	SECRET_KEY = qkd_get_key(qkd_socket, SESSION_ID)
	
	if(not qkd_close(qkd_socket, SESSION_ID)):
		print("Warning: problems in closing the connection with QKD network")

	print("Key setup finished!")
	print("[DEBUG] size of key: ", len(SECRET_KEY))

	input("Press ENTER to start " + app_mode)

	### DESERT connection
	print("Connecting to the DESERT framework: ", desert_address)
	desert_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
	desert_socket.connect(desert_address)

	if(app_mode == APP_MODE_TX):
		with open(filename, "r") as file:
			content = file.read()
		content = content.split("\n")[:-1]

		key_index = 0
		for payload in content:
			#We momentarely assume that the payload is of PAYLOAD_SIZE size
			print("Sending: ", payload)
			encr_payload = xor_payload(payload.encode(), key_index)
			key_index_header = key_index.to_bytes(length=HEADER_SIZE)
			desert_socket.send(key_index_header + encr_payload)
			key_index += 1
			time.sleep(1)
		print("TX done!")
		
	else: #app_mode == APP_MODE_RX
		while(True):
			data = desert_socket.recv(PACKET_SIZE)
			if(data == b""):
				print("RX done!")
				break
			
			key_index = int.from_bytes(data[:HEADER_SIZE])
			payload = xor_payload(data[HEADER_SIZE:], key_index)
			print("Raw: ", data)
			print("Received: ", payload.decode())
	
	#Releasing DESERT resources
	desert_socket.close()

