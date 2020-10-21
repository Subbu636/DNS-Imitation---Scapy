# imports
from scapy.all import *
import time
import threading

def getAck(s):
	global serverIP, serverPort
	while True:
		Ack = sniff(filter=f"tcp and host {serverIP} and port {sport}",count=1)
		if Ack[0][TCP].ack == 1 and Ack[0][TCP].seq == s:
			print("Acked-Sequence:"+str(s))
			break

# client program

serverIP = "10.0.2.15"
dport = 5005
sport = 5034

# 3 way hand shake

send(IP(dst=serverIP)/TCP(dport=dport,sport=sport)) # first hand shake
sniff(filter=f"tcp and host {serverIP} and port {sport}",count=1) # second
time.sleep(0.3)
send(IP(dst=serverIP)/TCP(dport=dport,sport=sport)) # third
print("Connected to Server")

# data transfer

data1 = b"hi"*500
data2 = b"by"*500
seq = 1

time.sleep(0.3)
send(IP(dst=serverIP)/TCP(dport=dport,sport=sport,seq=seq)/data1)
t1 = threading.Thread(target=getAck,args=(seq,))
t1.start()
seq+=1
time.sleep(0.6)
send(IP(dst=serverIP)/TCP(dport=dport,sport=sport,seq=seq)/data2)
t2 = threading.Thread(target=getAck,args=(seq,))
t2.start()
seq+=1
t1.join()
t2.join()
print("Data Sent Sucessfully")

# finishing up

time.sleep(0.6)
send(IP(dst=serverIP)/TCP(dport=dport,sport=sport,flags="F"))
getAck(0)
while True:
		Ack = sniff(filter=f"tcp and host {serverIP} and port {sport}",count=1)
		if str(Ack[0][TCP].flags) == "F":
			print("Acked-Finish")
			break
time.sleep(0.6)
send(IP(dst=serverIP)/TCP(dport=dport,sport=sport,ack=1))








