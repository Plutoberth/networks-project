import re
import time
import requests
import json

API_ADDR = "http://ip-api.com/json/{}"
PVT_IP_REGEX = [re.compile(r"^127.\d{1,3}.\d{1,3}.\d{1,3}$"),
                re.compile(r"^10.\d{1,3}.\d{1,3}.\d{1,3}$"),
                re.compile(r"^192.168.\d{1,3}$"),
                re.compile(r"^172.(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")]


class IpCountry:
    def __init__(self):
        self.ip_dict = {}  # Cache ip-country pairs.
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
        regex_results = [pattern.match(ip) for pattern in PVT_IP_REGEX]
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
                return "Private IP"  # Just in-case it slipped through the regex.

            else:
                return data_dict["country"]
        else:
            return "Private IP"
