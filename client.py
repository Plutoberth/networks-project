from scapy3k.all import *


def get_my_own_mac() -> str:
    p = srp1(Ether()/IP(dst="google.com", ttl=0) / ICMP() / "lorem", verbose=0)
    return p[Ether].dst  # This works because the first hop is our router.

