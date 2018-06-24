import socket
import json
import datetime
import sys
from ReportUploadWrapper import ReportUploader

SOCKET_DETAILS = ("127.0.0.1", 28972)

SETTINGS_PATH = "settings.dat"
JSON_PATH = "datastore.json"
TEMPLATE_PATH = r"HTML_Files\template.html"
FINAL_PATH = r"HTML_Files\final.html"
USERNAME = "nir_harel"


HTML_ASSOC_DICT = {'ext_port': "PORTS", 'ext_ip': "IPS", 'country': "COUNTRIES", 'traffic_incoming': "AGENTS_IN",
                   'traffic_outgoing': 'AGENTS_OUT', 'program': 'APPS', "alerts": "ALERTS"}


def read_dat_file(dat_path: str) -> dict:
    """
    The function reads the data file (only compliant files) and parses it.
    :param dat_path: The path to the data file.
    :return: a dictionary of the workers  of the blacklist.
    """
    try:
        with open(dat_path, "r") as f:
            file_lines = f.readlines()
    except FileNotFoundError:
        print("Couldn't open the settings file. Please put the proper settings file in the folder.")
        raise KeyboardInterrupt

    file_lines = [r.rstrip() for r in file_lines]

    workers_dict = {}
    blacklist_dict = {}

    # for reference, the format is "TYPE = entry_name:entry_data,entry_name:entry_data"
    workers = file_lines[0].split(" = ")[1].split(",")  # Get purely the workers
    blacklist = file_lines[1].split(" = ")[1].split(",")  # Get purely the blacklist

    for entry in workers:  # organize into a dict
        worker_split = entry.split(":")
        workers_dict[worker_split[1]] = worker_split[0]
        # I decided to flip the order of the workers because it makes more sense.
        # Typically we would want to search by IP, not by the name of the employees.

    for entry in blacklist:  # organize into a dict
        blacklist_split = entry.split(":")
        blacklist_dict[blacklist_split[0]] = blacklist_split[1]

    return {"workers": workers_dict, "blacklist": blacklist_dict}


def get_reports() -> (bytes, str):
    """
    A simple generator function that listens and returns UDP reports.
    :return: Data bytes, ip address.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # A regular UDP socket.
    sock.bind(SOCKET_DETAILS)

    while True:
        yield sock.recvfrom(256000)


def update_dict(dictionary: dict, key: str, value: int) -> None:
    """
    If the key is in the dictionary, add the value to it. Otherwise, put the key in the dictionary.
    :return: dicts are passed by reference so we don't need to return anything
    """
    if key in dictionary:
        dictionary[key] += value
    else:
        dictionary[key] = value


def update_json(data_dict, json_path, program_settings) -> None:
    """
    Updates the json file with our new data. Creates a new one if it doesn't exist.
    :param data_dict: A dictionary with the data from the agent.
    :param json_path:
    :param program_settings: A dict representing the data file.
    :return:
    """
    try:
        with open(json_path) as f:
            current_dict = json.loads(f.readline())

    except FileNotFoundError:
        current_dict = {'ext_ip': {}, 'country': {}, 'ext_port': {}, 'traffic_incoming': {}, 'traffic_outgoing': {},
                        'program': {}, 'alerts': []}

    for packet in data_dict["packets"]:
        if data_dict["pvt_ip"] in program_settings["workers"]:
            worker = program_settings['workers'][data_dict['pvt_ip']]
        else:
            worker = "Unknown"  # We could have a lot of unidentified agents on the network.

        packet_size = packet['packet_size']

        for field in ['ext_ip', 'country', 'ext_port', 'program']:  # Update the one case fields
            field_data = packet[field]
            update_dict(current_dict[field], field_data, packet_size)

        if packet["direction"] == "i":  # Incoming traffic
            update_dict(current_dict['traffic_incoming'], worker, packet_size)
        elif packet["direction"] == "o":  # Outgoing traffic
            update_dict(current_dict['traffic_outgoing'], worker, packet_size)

        if packet["ext_ip"] in program_settings["blacklist"]:
            if not any(r == [worker, packet["ext_ip"]] for r in current_dict["alerts"]):  # If the alert is not present.
                current_dict["alerts"].append([worker, packet["ext_ip"]])  # Append it.

    with open(json_path, "w") as f:  # Overwrite
        f.write(json.dumps(current_dict))


def update_in_list(lines, field_name, field_data):
    """Find an entry in our list and replace its values."""
    replace_line: int = [r[0] for r in enumerate(lines) if field_name in r[1]][0]
    lines[replace_line] = lines[replace_line].replace(field_name, field_data)


def update_html(json_path: str, template_path: str, final_path: str):
    """
    Creates a new html file from the template with the data in the json.
    :param json_path: The json to get the data from.
    :param template_path: The template to use.
    :param final_path: What we'll save the html file as.
    """
    try:
        with open(json_path) as f:
            data: dict = json.loads(f.readline())

        with open(template_path) as f:
            template: list = f.readlines()
    except FileNotFoundError:
        print("JSON or HTML template not found. Returning...")
        return

    for field_name, field_dict in data.items():
        if field_name != "alerts":
            html_name = HTML_ASSOC_DICT[field_name]  # Translate the value to the one mentioned in the html file.
            key_string = f"%%{html_name}_KEYS%%"
            value_string = f"%%{html_name}_VALUES%%"

            update_in_list(template, key_string, json.dumps(list(field_dict.keys())))  # Replace key entry

            update_in_list(template, value_string, json.dumps(list(field_dict.values())))  # Replace value entry

    timestamp_string = datetime.datetime.now().strftime("%a, %d of %B, %H:%M:%S")

    update_in_list(template, "%%TIMESTAMP%%", timestamp_string)
    update_in_list(template, "%%ALERTS%%", json.dumps(data["alerts"]))

    with open(final_path, "w") as f:
        f.writelines(template)


def main():
    program_settings = read_dat_file(SETTINGS_PATH)
    report_uploader = ReportUploader(FINAL_PATH, USERNAME, upload_frequency=240)
    packets_recorded = 0

    for data, addr in get_reports():
        data_dict = json.loads(data.decode())
        packets_recorded += len(data_dict['packets'])

        update_json(data_dict, JSON_PATH, program_settings)
        update_html(JSON_PATH, TEMPLATE_PATH, FINAL_PATH)
        web_save = report_uploader.update_html()
        if web_save:
            print("\nReport saved and uploaded to {}, with {} new packets.".format(web_save, packets_recorded))
            packets_recorded = 0
        else:
            sys.stdout.write("\rReceiving data... ({} new packets since last upload)".format(packets_recorded))


if __name__ == '__main__':
    main()
