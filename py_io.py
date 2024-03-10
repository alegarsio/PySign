import binascii
import socket
import requests
import logging
import ipaddress
import sys
import base64
import struct
import time
import psutil
from collections import deque
import matplotlib.pyplot as plt
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# (c) Alegrarsio gita on https://github.com/alegarsio
# NetMouse Project

"""
 _ __      ((o))              
' )  )      /\         
 /--'__  , /  )  o _,  ____ 
/   / (_/_/__/__<_(_)_/ / <_
       /           /|       
      '           |/    Version.1.0    
"""

list_Proto = [
            "TCP",
            "UDP",
            "ICMP" 
            ]

class SignalStream:
    def __init__(self):
        self.network_speeds = deque(maxlen=50)
        self.times = deque(maxlen=50)
    def network_speed(self):
        network_speed = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        return network_speed
    def update(self):
        plt.clf()
        plt.plot(self.times, self.network_speeds)
        plt.xlabel('Time')
        plt.ylabel('Network Speed In (Bytes)')
        plt.title('Network Speed')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.pause(0.1)

    def run(self):
        try:
            while True:
                network_speed = self.network_speed()
                self.network_speeds.append(network_speed)
                self.times.append(time.strftime('%H:%M:%S'))
                self.update()
                time.sleep(1) 
        except KeyboardInterrupt:
            pass
        plt.show()
        
class Sniff:
    def __init__(self):
        self.traffic = []

    def sniff(self):
        if sys.platform.startswith('win'):
            return
        try:
            con = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            while True:
                raw_data, addr = con.recvfrom(65536)
                dest_mac, src_mac, eth_proto = self.ether_frame(raw_data)
                summary = self.summary(dest_mac, src_mac, eth_proto)
                self.traffic.append(summary)
        except KeyboardInterrupt:
            pass

    def ether_frame(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto)

    def get_mac_addr(self, b_addr):
        bytes_str = map('{:02x}'.format, b_addr)
        return ':'.join(bytes_str).upper()

    def summary(self, dest_mac, src_mac, eth_proto):
        return 'Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto)

    def show(self):
        for item in self.traffic:
            print(item)
class HTTP:
    def Request(dst_address , dst_port , request_send):
        socket.gethostbyname(dst_address)
        with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as sock:
            try:
                sock.connect((dst_address,dst_port))
                sock.sendall(request_send.encode())
                response = b""
                while True:
                    data = sock.recv(1024)
                    if not data : 
                        break
                    response += data
                sock.close()
                return response.decode()    
            except Exception as e: 
                return "Error : {}".format(e)
    def Get(dst_address = str):
        hostname, path = dst_address.split('/', 1)
        path = '/' + path
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.connect(hostname,80)
            sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n".encode())  
            response = b""
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                response += data
            headers, html = response.split(b'\r\n\r\n', 1)
            return html.decode()      
class Packet:
    def Interface():
        with socket.socket(socket.AF_PACKET ,socket.SOCK_RAW , socket.ntohs(3)) as sock:
            try:
                pkt_buffer = sock.recvfrom(65565)
                pkt_data = pkt_buffer[0]
                address = pkt_buffer[1]
                return "Packet Received from {}".format(address)
            except PermissionError:
                return "Permission denied"
            except socket.gaierror:
                return "Can not request host"
            except socket.error:
                return "Failed to make connection"
    def Send(dst_address = str , dst_port = int , msg = str , proto = str):
        socket.gethostbyname(dst_address)
        try:
            if proto.startswith(list_Proto[0]):
                with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as tcp:
                    tcp.connect((dst_address,dst_port))
                    if (tcp.send(msg.encode()) == len(msg)):
                        return 0
                    return 1
            elif proto.startswith(list_Proto[1]):
                with socket.socket(socket.AF_INET , socket.SOCK_DGRAM) as udp:
                    udp.connect((dst_address , dst_port))
                    udp.sendall(msg,(dst_address,dst_port))
                    return 0
        except socket.gaierror:
            return "Error , Can not request address"
        except socket.error:
            return "Error , Fail to make connection"
    def Receive(src_address = str , src_port = int , listens = int , proto = str):
        socket.gethostbyname(src_address)
        try:
            if proto.startswith(list_Proto[0]):
                with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as tcp:
                    tcp.bind((src_address,src_port))
                    tcp.listen(listens)
                    con , addr = tcp.accept()
                    data = con.recv(1024)
                    return "Recieved From {} , MSG : {}".format(addr , data.decode())
            elif proto.startswith(list_Proto[1]):
                with socket.socket(socket.AF_INET , socket.SOCK_DGRAM) as udp:
                    udp.bind((src_address,src_port))
                    udp.listen(listens)
                    con , addr = udp.accept()
                    data = con.recv(1024)
                    return "Recieved From {} , MSG : {}".format(addr , data.decode())
        except socket.gaierror : 
            return "Error , can not request address"
        except socket.error :
            return "Error , Fail to make connection"
    
        
        
