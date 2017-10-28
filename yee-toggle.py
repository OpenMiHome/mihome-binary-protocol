import miio
import socket
import struct

def main():
	TARGET_IP = "192.168.13.1"
	MY_IP = "192.168.13.3"
	UDP_PORT = 54321
	pkt_hello = bytes.fromhex("21 31 00 20 ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff")
	payload_toggle = bytes.fromhex("7b 22 69 64 22 3a 31 2c 22 6d 65 74 68 6f 64 22 3a 22 74 6f 67 67 6c 65 22 2c 22 70 61 72 61 6d 73 22 3a 5b 5d 7d")
	stamp = 0

	sock = socket.socket(socket.AF_INET, # Internet
		             socket.SOCK_DGRAM) # UDP
	sock.bind((MY_IP, UDP_PORT))
	print("open socket")

	sock.sendto(pkt_hello, (TARGET_IP, UDP_PORT))
	print("sending hello")


	while True:
		data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
		break

	print("received message:", data)
	miio.print_head(data)
	head = data[:32]
	magic, packet_len, unknown1, did, stamp, token = \
	struct.unpack('!2sHIII16s', head)
	
	pkt_toggle = miio.encrypt(stamp+10,did,token,payload_toggle)
	print("sending message:", data)
	miio.print_head(pkt_toggle)
	sock.sendto(pkt_toggle, (TARGET_IP, UDP_PORT))
	print("message sent")

	while True:
		data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
		break

	print("received message:", data)
	miio.print_head(data)

if __name__ == "__main__":
    main()



