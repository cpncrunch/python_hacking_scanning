#!/usr/bin/python
#-*- coding:utf-8 -*-
#Author: Isaac Privett
#Date: 05-01-2022
#Description: Port scanner to grab banners

import socket
import os
import sys
from threading import *
from termcolor import colored
from socket import *

def portScan(ip, port):
	t = Thread(target=connScan, args=(ip, int(port)))
	t.start()
	
def connScan(ip, port):
	try:
		sock = socket(AF_INET, SOCK_STREAM)
		sock.connect((ip,port))
		banner = sock.recv(1024)
		#print(colored('[+] Port %d/tcp Open ' % port,'green'))
		if banner:
			print(colored('[+] Port '+ str(port) + '/tcp Open Banner: ' + str(banner),'green'))#print("[+] Banner: "+ str(banner))
		else:
			print(colored('[+] Port %d/tcp Open ' % port,'green'))
		sock.close()
	except:
		return
		#print(colored('[-] %d/tcp Closed' % port, 'red'))
	#finally:
		#sock.close()

def checkVulns(banner, filename):
	f = open(filename, "r")
	for line in f.readlines():
		if line in str(banner):
			print("[+] Server is vulnerable: " + str(banner))

def main():
	
	#portlist = [21,22,25,80,110,443,445]
	#for x in range(1,256): uncomment out if want to do whole local network
	#ip = "192.168.1." + str(x)
	ip = input("Enter host to scan: ")
	
	print(colored('[*] Scan results for: ' + ip, 'blue'))
	try:
		for port in range(1,65535): #in portlist if want a specific port list
			portScan(ip,port)
	except:
		print("Host not found!")
		quit()
		

main()
