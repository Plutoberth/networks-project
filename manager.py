import socket

SOCKET_DETAILS = ("", 28972)

SETTINGS_PATH = "settings.dat"


def read_dat_file(dat_path: str) -> (dict, dict):
    """
    The function reads the data file (only compliant files) and parses it.
    :param dat_path: The path to the data file.
    :return: a dictionary of the workers and a dictionary of the blacklist in a tuple.
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

    return workers_dict, blacklist_dict


def get_reports() -> (bytes, str):
    """
    A simple generator function that listens and returns UDP reports.
    :return: Data bytes, ip address.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # A regular UDP socket.
    sock.bind(SOCKET_DETAILS)

    while True:
        yield sock.recvfrom(128000)


def main():
    workers, blacklist = read_dat_file(SETTINGS_PATH)

    for data, addr in get_reports():







if __name__ == '__main__':
    main()
