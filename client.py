from scapy3k.all import *
import requests
import json

API_ADDR = "http://ip-api.com/json/{}"


def get_country(ip: str) -> str:
    """
    Gets the country of an ip.
    :param ip: String of an ip.
    :return: Country string.
    """
    ip_data = requests.get(API_ADDR.format(ip)).content
    data_dict = json.loads(ip_data)
    if data_dict["status"] == "fail":
        return "Private IP"

    else:
        return data_dict["country"]


def get_local_details() -> dict:
    p = srp1(Ether() / IP(dst="google.com", ttl=0) / ICMP() / "lorem", verbose=0)
    data_dict = {"my_mac": p[Ether].dst, "gateway_mac": p[Ether].src, "my_ip": p[IP].dst, "gateway_ip": p[IP].src}
    return data_dict


print(get_local_details())

