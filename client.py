from scapy3k.all import *
import requests
import json
import subprocess
import threading

API_ADDR = "http://ip-api.com/json/{}"
PACKET_AMOUNT = 200
LAN_DETAILS = {}
PACKET_DATA = []
MANAGER_DETAILS = ("127.0.0.1", 28972)
NETSTAT_REGEX = r"({} .+)([^\[])* \[([a-zA-Z.]+)]"
PVT_IP_REGEX = [re.compile(r"^127.\d{1,3}.\d{1,3}.\d{1,3}$"),
                re.compile(r"^10.\d{1,3}.\d{1,3}.\d{1,3}$"),
                re.compile(r"^192.168.\d{1,3}$"),
                re.compile(r"^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")]

# Program must be ran in elevated privileges mode (i.e. Administrator) for the program field to work.


class IpCountry:
    def __init__(self):
        self.ip_dict = {}  # Store associations
        self.num = 0
        self.delay = 1

    def __getitem__(self, ip):
        """
        Gets the IP's country and caches it.
        :param ip: The ip to get the country for.
        :return: The country
        """
        if ip not in self.ip_dict:
            self.ip_dict[ip] = self.get_country(ip)
        return self.ip_dict[ip]

    def get_country(self, ip: str) -> str:
        """
        Gets the country of an ip.
        :param ip: String of an ip.
        :return: Country string.
        """

        regex_results = [pat.match(ip) for pat in PVT_IP_REGEX]
        if all(not r for r in regex_results):  # If all values were none (i.e. external IP)
            try:
                time.sleep(self.delay)
                if ip not in self.ip_dict:  # Some other thread might've looked it up in the meantime (while we waited)
                    ip_data = requests.get(API_ADDR.format(ip))
                    self.num = self.num + 1
                else:
                    return self.ip_dict[ip]

            except requests.exceptions.RequestException as e:  # All requests exceptions inherit from this exception
                print(e)
                return "Unknown"

            data_dict = json.loads(ip_data.content)
            if data_dict["status"] == "fail":
                return "Private IP"  # Just incase it slipped through the regex.

            else:
                return data_dict["country"]
        else:
            return "Private IP"


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
        sock.sendto(bytes(json.dumps(data_dict), "utf-8"), MANAGER_DETAILS)


def sniff_filter(packet: Packet):
    if IP in packet:
        return UDP in packet or TCP in packet


def get_netstat_output() -> str:
    """Returns the output of the netstat command."""
    netstat = subprocess.Popen(["netstat", "-nb"], stdout=subprocess.PIPE).stdout  # Use the netstat command
    netstat = [r.decode() for r in netstat]  # Decode the bytes
    netstat = "".join(netstat)  # Join the output into a single string.
    return netstat


def get_program(local_port: int) -> str:
    """Returns a string of the program that is using the specified local port using netstat."""
    local_ip = LAN_DETAILS["my_ip"]
    local_conn = f"{local_ip}:{local_port}"  # This is the unique connection we need to find within the netstat output.
    netstat_output = get_netstat_output()

    local_conn = local_conn.replace(".", r"\.")  # . is a character that represents any character on regex.
    conn_regex = NETSTAT_REGEX.format(local_conn)  # Format the connection details into the regex pattern.

    re_match = re.search(conn_regex, netstat_output, re.MULTILINE)  # Search for it
    if re_match:  # If matched
        program = re_match.group(3)  # get group number 3, which is the exe.
    else:
        program = "Unknown"  # Just return a generic unknown.

    return program


def record_details(packet: Packet):
    """Because the conversation might end until we finish sniffing, we have to record the program at runtime.
       We already have to get this data so we'll store it in a dictionary for the handler."""
    packet_transport = packet[UDP] if UDP in packet else packet[TCP]
    direction = "i"
    global LAN_DETAILS
    if LAN_DETAILS["my_mac"] == packet[Ether].src:
        direction = "o"

    if direction == "i":  # Get external details.
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
                       program=program)  # Store in dictionary.

    PACKET_DATA.append(packet_dict)


def get_local_details() -> dict:
    p = srp1(Ether() / IP(dst="google.com", ttl=0) / ICMP() / "lorem", verbose=0)
    data_dict = {"gateway_ip": p[IP].src, "my_ip": p[IP].dst, "my_mac": p[Ether].dst}
    return data_dict


def adjust_delay(ip_class, thread_list):
    """Adjusts the delay to the ip class based on the number of threads currently active."""
    if len(thread_list) > 1:
        ip_class.delay = 0.5 * len(thread_list)  # Adjust the delay based on the number of threads running.
    else:
        ip_class.delay = 0.5

def main():
    global LAN_DETAILS
    global PACKET_DATA
    LAN_DETAILS = get_local_details()
    ip_country = IpCountry()
    threads = []
    try:
        while True:
            PACKET_DATA = []
            threads = [t for t in threads if t.is_alive()]
            sniff(lfilter=sniff_filter, prn=record_details, count=PACKET_AMOUNT)
            curr_thread = PacketHandler(PACKET_DATA.copy(), ip_country)
            curr_thread.start()
            threads.append(curr_thread)
            adjust_delay(ip_country, threads)
            print("Added data package to queue ({} packets). {} awaiting transmission.".format(PACKET_AMOUNT
                                                                                               , len(threads)))

    except KeyboardInterrupt:
        print("Aborted agent operation.")


if __name__ == '__main__':
    main()

