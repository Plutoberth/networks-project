from scapy3k.all import *
import json
import subprocess
import threading
from CountryHandler import IpCountry


PACKET_AMOUNT = 200
LAN_DETAILS = {}
PACKET_DATA = []
MANAGER_DETAILS = ("127.0.0.1", 28972)
NETSTAT_REGEX = r"({} .+)([^\[])* \[([a-zA-Z.]+)]"


# Program must be ran in elevated privileges mode (i.e. Administrator) for the program field to work.

class PacketHandler(threading.Thread):
    def __init__(self, packets, countries):
        self.packets = packets
        self.countries = countries
        super().__init__()  # Required to activate the thread

    def run(self):
        """Adds the country field to the dictionary and sends it to the server."""
        data_dict = dict(pvt_ip=LAN_DETAILS["my_ip"], packets=[])

        for packet in self.packets:
            ext_ip = packet["ext_ip"]
            packet["country"] = self.countries[ext_ip]  # Fetches the country. Note: may block for a very long time.
            data_dict['packets'].append(packet)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP socket
        sock.sendto(bytes(json.dumps(data_dict), "utf-8"), MANAGER_DETAILS)
        print("Transmitted data package ({} packets)".format(PACKET_AMOUNT))


def sniff_filter(packet: Packet):
    """A very simple filter to check if there is a UDP or TCP transport layer in the packet."""
    if IP in packet:
        return UDP in packet or TCP in packet


def get_netstat_output() -> str:
    """Returns the output of the netstat command."""
    netstat = subprocess.Popen(["netstat", "-nb"], stdout=subprocess.PIPE).stdout  # Use the netstat command
    netstat = [r.decode() for r in netstat]  # Decode the bytes for each line
    netstat = "".join(netstat)  # Join the output into a single string.
    return netstat


def get_program(local_port: int) -> str:
    """Returns a string of the program that is using the specified local port using netstat."""
    local_ip = LAN_DETAILS["my_ip"]
    local_conn = f"{local_ip}:{local_port}"  # This is the unique connection we need to find within the netstat output.
    netstat_output = get_netstat_output()

    # . is a special char that represents any character on regex, so we have to escape it with a backslash.
    local_conn = local_conn.replace(".", r"\.")
    conn_regex = NETSTAT_REGEX.format(local_conn)  # Format the connection details into the regex pattern.

    re_match = re.search(conn_regex, netstat_output, re.MULTILINE)  # Search for it
    if re_match:  # If matched
        program = re_match.group(3)  # get group number 3, which contains the name of the program.
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
    """Gets the details about the local network."""
    p = srp1(Ether() / IP(dst="google.com", ttl=0) / ICMP() / "lorem", verbose=0)
    data_dict = {"gateway_ip": p[IP].src, "my_ip": p[IP].dst, "my_mac": p[Ether].dst}
    return data_dict


def adjust_delay(ip_class, thread_list):
    """Adjusts the delay to the ip class based on the number of threads currently active."""
    if len(thread_list) > 1:
        ip_class.delay = 0.5 * len(thread_list)  # Adjust the delay based on the number of threads running.
    else:
        ip_class.delay = 0.5


def check_admin():
    if "The requested operation requires elevation." in get_netstat_output():
        print("WARNING: The agent will not report program usage to the manager as it doesn't have admin privileges.")


def main():
    global LAN_DETAILS
    global PACKET_DATA
    LAN_DETAILS = get_local_details()
    ip_country = IpCountry()
    threads = []
    check_admin()  # Notify the user if the client can't report programs.

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
                                                                                               , len(threads) - 1))

    except KeyboardInterrupt:
        print("Aborted agent operation.")
        raise KeyboardInterrupt


if __name__ == '__main__':
    main()

