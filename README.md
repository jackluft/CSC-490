# CSC-490- Midterm Assignment: 
This script simulates a Distributed Denial-of-Service (DDoS) using Scapy. The program starts off by preforming a port scan on the provided attack IP. After the scan has been completed it will then list all the open ports where a attack can be preformed. The user will then have the option to select a open port. Once an open port has been selected the program will launch a TCP SYN flood attack on the attacked machine.
## Features include: <br>
. Multi-threaded attack simulation <br>
. Randomized packet generation <br>
. Port Scanning <br>
. TCP SYN flooding <br>

## REQUIRMENTS: <br>
. Python 3.x <br>
. scapy  <br>
. tqdm <br> 
. colorama <br>

## Usage:

Run the script with the following command: <br>
$python ddos.py <target_ip>
<br>
$python ddos.py <target_ip> --port <startPort:endPort>
<br>
$python ddos.py <target_ip> --attack <PortNumber>

Arguments: 
-----------------------------------------------------------
--port: The range of the port scan (e.g., --port 80:100) <br>
--attack: This will skip the port scan and preform the TCP SYN flood attack on the provided port number. <br>
Note: port and attack arguments CAN NOT both be provided.


Ethical Considerations
-----------------------------------------------------------
This tool should only be used on networks and systems where you have explicit permission. Misuse can lead to legal consequences.



