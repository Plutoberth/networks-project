from scapy3k.all import *
import requests
import json
import threading

API_ADDR = "http://ip-api.com/json/{}"
PACKET_AMOUNT = 100
LAN_DETAILS = {}
PACKET_DATA = []
MANAGER_DETAILS = ("127.0.0.1", 28972)


class IpCountry:
    def __init__(self):
        self.ip_dict = {}  # Store associations

    def __getitem__(self, ip):
        """
        Gets the IP's country and caches it.
        :param ip: The ip to get the country for.
        :return: The country
        """
        if ip not in self.ip_dict:
            self.ip_dict[ip] = self.get_country(ip)
        return self.ip_dict[ip]

    @staticmethod
    def get_country(ip: str) -> str:
        """
        Gets the country of an ip.
        :param ip: String of an ip.
        :return: Country string.
        """

        try:
            ip_data = requests.get(API_ADDR.format(ip))
            time.sleep(5)
            print(ip)
        except requests.exceptions.RequestException as e:  # All requests exceptions inherit from this exception
            print(e)
            return "Unknown"

        data_dict = json.loads(ip_data.content)
        if data_dict["status"] == "fail":
            return "Private IP"

        else:
            return data_dict["country"]


class PacketHandler(threading.Thread):
    def __init__(self, packets, countries):
        self.packets = packets
        self.countries = countries
        super().__init__()

    def run(self):
        """Adds the country field to the dictionary and sends it to the server."""
        data_dict = dict(pvt_ip=LAN_DETAILS["my_ip"], packets=[])

        for packet in self.packets:
            ext_ip = packet["ext_ip"]
            packet["country"] = self.countries[ext_ip]
            data_dict['packets'].append(packet)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        print(data_dict)
        sock.sendto(bytes(json.dumps(data_dict), "utf-8"), MANAGER_DETAILS)


def sniff_filter(packet: Packet):
    if IP in packet:
        return UDP in packet or TCP in packet

def get_program(local_port: int) -> str:
    """Returns a string of the program that is using the specified local port using netstat."""
    local_ip = LAN_DETAILS["my_ip"]
    local_conn = f"{local_ip}:{local_port}"  # This is the unique connection we need to find within the netstat output.
    return "Unknown"


def record_details(packet: Packet):
    """Because the conversation might end until we finish sniffing, we have to record the program at runtime.
       We already have to get this data so we'll store it in a dictionary for the handler."""
    packet_transport = packet[UDP] if UDP in packet else packet[TCP]
    direction = "i"
    global LAN_DETAILS
    if LAN_DETAILS["my_mac"] == packet[Ether].src:
        direction = "o"

    if direction == "i":
        ext_ip = packet[IP].src
        ext_port = packet_transport.sport
        local_port = packet_transport.dport
    else:
        ext_ip = packet[IP].dst
        ext_port = packet_transport.dport
        local_port = packet_transport.sport

    packet_size = len(packet)

    program = get_program(local_port)

    packet_dict = dict(ext_ip=ext_ip, ext_port=ext_port, direction=direction, packet_size=packet_size, country="",
                       program=program)

    PACKET_DATA.append(packet_dict)


def get_local_details() -> dict:
    p = srp1(Ether() / IP(dst="google.com", ttl=0) / ICMP() / "lorem", verbose=0)
    data_dict = {"gateway_ip": p[IP].src, "my_ip": p[IP].dst, "my_mac": p[Ether].dst}
    return data_dict


def main():
    global LAN_DETAILS
    global PACKET_DATA
    LAN_DETAILS = get_local_details()
    ip_country = IpCountry()
    threads = []
    try:
        while True:
            PACKET_DATA = []
            threads = [t for t in threads if not t.is_alive()]
            print(threads)
            sniff(lfilter=sniff_filter, prn=record_details, count=PACKET_AMOUNT)
            curr_thread = PacketHandler(PACKET_DATA.copy(), ip_country)
            curr_thread.start()
            threads.append(curr_thread)


    except KeyboardInterrupt:
        print("Aborted agent operation.")



if __name__ == '__main__':
    main()

