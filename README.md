## DNS Imitation
This project involves 2 systems (client and server) connected in a network
Here our client instead of sending DNS requests to its DNS host sends it to server and the server manages it
Our Server constructs DNS reply packets from known information and sends it to client
Everything is done using scapy 