import socket

class ReportUploader:
    """A simple wrapper of the ReportUploader protocol."""
    def __init__(self, html_path, username, server_details: tuple = ("54.71.128.194", 8808)):
        """

        :param html_path: The path to the HTML file we want to send to the server.
        :param username: The username to use the protocol with.
        :param server_details: A tuple containing the server address and port.
        """
        assert username  # Because we might get it from user input
        self.html_path = html_path
        self.username = username
        self.server_details = server_details

    def _read_file(self):
        """Internal use. Simply reads the html file the class was constructed with, and returns the string."""
        with open(self.html_path) as f:
            return "\n".join(f.readlines())

    def update_html(self):
        """Updates the html file on the server."""
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect(self.server_details)

        #Ask the server if our username is valid
        conn.send(f"400#USER={self.username}".encode())

        if conn.recv(2048).decode() != "405#USER OK":
            raise Exception("Invalid username!")

        html_contents = self._read_file()
        conn.send(f"700#SIZE={len(html_contents)},HTML={html_contents}")

        if conn.recv(2048).decode() != f"705#FILE SAVED TO {self.username}.bossniffer.com":
            raise Exception("Invalid HTML File!")

        conn.send("900#BYE".encode())  # Gracefully terminate.
        conn.close()




