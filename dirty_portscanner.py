#!/usr/bin/python3

from threading import Thread
from socket import AF_INET,SOCK_STREAM,socket
from argparse import ArgumentParser


class DirtyPortScanner:
    def save_result(self,s):
        if self.output_filename:
            try:
                with open(self.output_filename,"a+") as f:
                    f.writelines(s)
            except:
                print("Could not write to " + self.output_filename)

    def __init__(self, addr, p, threads, max, banner, timeout,output):
        self.addr = addr
        self.port_ranges = []  # 1-100,245,3000-4000
        self.max_threads = threads
        self.max_tries = max
        self.display_banner = banner
        self.timeout = timeout
        self.port_range_display = p
        self.output_filename = output

        for each_port_range in p.split(","):
            l = []
            for port_boundary in each_port_range.split("-"):
                l.append(int(port_boundary))
            self.port_ranges.append(l)

        self.threads_running = 0
        self.found_ports = []
        self.threads = []

    def start(self):
        initial = "SCAN OPTIONS SET\n----------------\nTarget host => " + self.addr + '\nTarget port ranges => ' + self.port_range_display + '\nMax concurrent threads => ' + str(self.max_threads) + '\n' + "Max tries per port => " + str(self.max_tries) + "\nTimeout per probe => " + str(self.timeout) + ' secs' + "\nDisplay grabbed banner => " + str(self.display_banner) + '\n'
        print('\n' + initial,end="")
        if self.output_filename:
            print("Save scan results to file => " + self.output_filename)
            self.save_result(initial)
        print("\nSCANNING\n----------------")
        for each_port_range in self.port_ranges:
            if len(each_port_range) == 2:
                for port in range(each_port_range[0], each_port_range[1] + 1):
                    thread = Thread(target=self.scan_port, args=(self.addr, port))
                    while True:
                        if self.threads_running < self.max_threads:
                            thread.start()
                            self.threads.append(thread)
                            self.threads_running += 1
                            break
            else:
                thread = Thread(target=self.scan_port, args=(self.addr, each_port_range[0]))
                while True:
                    if self.threads_running < self.max_threads:
                        thread.start()
                        self.threads.append(thread)
                        self.threads_running += 1
                        break

        for thread in self.threads:
            thread.join()
        print("\r" + " " * 24 + "\n[+] All specified ports scanned!\n\nRESULTS\n----------------\n[+] Found " + str(
            len(self.found_ports)) + " open port/s\n")
        self.save_result("\nSCAN RESULTS\n----------------\n[+] Found " + str(len(self.found_ports)) + " open port/s\n\n")

        if len(self.found_ports) != 0:
            if self.display_banner:
                i = 1
                for port_and_banner in self.found_ports:
                    print("[" + str(i) + "] Port -> " + str(port_and_banner[0]))
                    print("    Banner -> " + port_and_banner[1], end="\n\n")

                    self.save_result("[" + str(i) + "] Port -> " + str(port_and_banner[0]) + '\n')
                    self.save_result("    Banner -> " + port_and_banner[1] + "\n\n")

                    i += 1
            else:
                line = "[+] Ports open => "
                for port in self.found_ports:
                    line += str(port[0]) + ","
                print(line[:-1])
                print("")
                self.save_result(line[:-1] + '\n\n')

    # Thread function
    def scan_port(self, addr, port):
        client = socket(AF_INET, SOCK_STREAM)
        client.settimeout(self.timeout)
        port_and_banner = []
        try:
            print("\rTrying port " + str(port) + ' ...', end="")
            client.connect((addr, port))
            response = client.recv(1024)
            if len(response) != 0:
                print("\r[+] Found port " + str(port))
                try:
                    r = response.decode().strip()
                except UnicodeDecodeError:
                    r = "Cannot decode"
                port_and_banner.append(port)
                port_and_banner.append(r)
                self.found_ports.append(port_and_banner)
            else:
                for try_num in range(0, self.max_tries + 1):
                    client.sendall(b"some_random_junk_to_just_probe")
                    response = client.recv(1024)
                    if len(response) != 0:
                        print("\r[+] Found port " + str(port))
                        try:
                            r = response.decode().strip()
                        except UnicodeDecodeError:
                            r = "Cannot decode"
                        port_and_banner.append(port)
                        port_and_banner.append(r)
                        self.found_ports.append(port)
                        break

        except Exception:
            pass

        finally:
            client.close()
            self.threads_running -= 1
            return


# MAIN
# Usage: portscan.py -a address -p port_range -t threads --banner -m max_tries
parser = ArgumentParser(description="DirtyPortScanner simply scans the range of ports you supply and "
                                    "shows which one of them might be open. This it does by connecting "
                                    "to each specified port and checking if something comes back as a "
                                    "response. If it doesn't, a junk string is sent to the port and then "
                                    "it is checked again if there's any response. This is repeated for a specified "
                                    "number of times to probe the port till specified timeout.",
                        add_help=True, epilog="Author: CaptainWoof | "
                                              "Twitter: @realCaptainWoof")
parser.add_argument("-a", "--address", action='store', type=str, required=True, help="The destination host to probe")
parser.add_argument("-p", "--port-range", action='store', type=str, required=True, help="The ports to probe; separate "
                                                                                        "ports by a comma ',', ranges by "
                                                                                        "a hyphen '-' | Example: 1-1000,3289,4444,8000-9000...")
parser.add_argument("-t", "--threads", action="store", type=int, required=False, default=10, help="The maximum number "
                                                                                                  "of concurrent threads "
                                                                                                  "to use; default is 10")
parser.add_argument("-m", "--max-tries", action='store', type=int, required=False, default=3, help="Maximum number of "
                                                                                                   "retries for probing "
                                                                                                   "each port: default is 3")
parser.add_argument("-u", "--timeout", action='store', type=float, required=False, default=3.0,
                    help="Maximum number of "
                         "seconds to wait for each "
                         "probe's response; default is "
                         "3 seconds")
parser.add_argument("-b", "--banner", action="store_true", default=False, required=False,
                    help="Display grabbed banner; "
                         "non-default")
parser.add_argument("-o","--output",action='store',type=str,required=False,default=False,
                    help="Save scan results to a file with specified filename")
argv = parser.parse_args()

port_scanner = DirtyPortScanner(argv.address, argv.port_range, argv.threads, argv.max_tries, argv.banner, argv.timeout,
                                argv.output)
port_scanner.start()
