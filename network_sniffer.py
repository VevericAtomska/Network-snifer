import socket
 

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind(("0.0.0.0", 0))
 

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
 
try:
    while True:
       
        raw_data, addr = sniffer.recvfrom(65565)
        print(raw_data)
        
        with open("network_log.txt", "a") as f:
            f.write(str(raw_data) + "\n")
except KeyboardInterrupt:
    
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)