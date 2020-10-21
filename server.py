# imports
from scapy.all import *
import time
import threading

def putAck(s):
	global dstn_ip, dport, sport
	time.sleep(0.3)
	send(IP(dst=dstn_ip)/TCP(dport=dport,sport=sport,seq=s,ack=1))
	print("Acked Sequence:"+str(s))

# server program
sport = 5005
print("Started...")

# listning at the port

h1 = sniff(filter=f"tcp and port {sport}",count=1,
	timeout=300) # first of 3 way handshake
dport = h1[0][TCP].sport
time.sleep(0.3)
send(IP(dst=h1[0][IP].src)/TCP(dport=dport,
	sport=sport,ack=0)) # second
h3 = sniff(filter=f"tcp and host {h1[0][IP].src} and port {sport}",
	count=1) # third
dstn_ip = h1[0][IP].src
print("Connected to :")
print(dstn_ip,sport)

# data transfer

data = []
threads = []

while True:
	pckt = sniff(filter=f"tcp and host {dstn_ip} and port {sport}",
		count=1)
	if pckt[0][TCP].ack == 1:
		continue
	flag = pckt[0][TCP].flags
	s = pckt[0][TCP].seq
	if str(flag) == "F":
		break
	if Raw in pckt[0]:
		data.append(pckt[0][Raw].load)  # r[0][Raw].load
	print("Recieved Sequence:"+str(s))
	#putAck(s)
	t = threading.Thread(target=putAck,args=(s,))
	t.start()
	threads.append(t)
		
# finishing up

for t in threads:
	t.join()

time.sleep(0.3)
send(IP(dst=dstn_ip)/TCP(dport=dport,sport=sport,ack=1))
time.sleep(0.3)
send(IP(dst=dstn_ip)/TCP(dport=dport,sport=sport,flags="F"))
Ack = sniff(filter=f"tcp and host {dstn_ip} and port {sport}",count=1)
if (Ack[0][TCP].ack) == 1:
	print(data)
	print("Connection closed")
else:
	print("Connection closed Badly")

print("Ended")

	
	
	
	
	
	
