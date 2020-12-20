#!/usr/bin/python3

from threading import Thread
from socket import AF_INET, SOCK_STREAM, socket
from argparse import ArgumentParser
from subprocess import Popen, PIPE, STDOUT
from time import sleep


class DirtyPortScanner:
    def save_result(self, s):
        if self.output_filename:
            try:
                with open(self.output_filename, "a+") as f:
                    f.writelines(s)
            except:
                print("Could not write to " + self.output_filename)

    def Selected(self, text):
        return '\33[7m' +'\33[1m' + text + '\033[0m'

    def Redbg(self, text):
        return '\33[41m' +'\33[1m' + text + '\033[0m'

    def Greenbg(self, text):
        return '\33[42m' +'\33[1m' + text + '\033[0m'

    def Bluebg2(self, text):
        return '\33[104m' +'\33[1m' + text + '\033[0m'

    def __init__(self, addr, p, threads, max, timeout, output, nmap, nmapPorts, nmapPath, junk, junkFile, b):
        self.addr = addr
        self.port_ranges = []  # 1-100,245,3000-4000
        self.max_threads = threads
        self.max_tries = max
        self.timeout = timeout
        self.port_range_display = p
        self.output_filename = output
        self.nmap = nmap
        self.nmap_ports = nmapPorts
        self.nmap_path = nmapPath
        self.junk = junk.encode()
        self.jfname = junkFile
        self.full_banner = b

        for each_port_range in p.split(","):
            l = []
            for port_boundary in each_port_range.split("-"):
                l.append(int(port_boundary))
            self.port_ranges.append(l)

        self.threads_running = 0
        self.found_ports = []
        self.threads = []

        if self.jfname is not None:
            try:
                with open(self.jfname, 'rb') as f:
                    line = f.readlines()
                self.junk = b"".join(line)
            except FileNotFoundError:
                print("\n"+self.Redbg(" ! ")+" Probe strings file not found!\n    Continuing with default...")
            except:
                print("\n"+self.Redbg(" ! ")+"Encountered error while reading probe strings file!\n    Continuing with default...")

    def start(self):
        initial = self.Selected("[+]")+" CONFIGURATION"
        initial += "\n----------------"
        initial += "\nTarget host => " + self.addr
        initial += '\nTarget port ranges => ' + self.port_range_display
        initial += '\nMax concurrent threads => ' + str(self.max_threads)
        initial += "\nMax tries per port => " + str(self.max_tries)
        initial += "\nTimeout per probe => " + str(self.timeout) + ' secs'
        initial += "\nString to probe with => "
        try:
            initial +=  str(self.junk)
        except UnicodeDecodeError:
            initial += "Could not be decoded to show here"
        if self.nmap:
            initial += "\nNmap args => " + str(self.nmap)
            initial += "\nNmap ports => " + self.nmap_ports
            initial += "\nNmap path => " + self.nmap_path

        print('\n' + initial, end="")
        if self.output_filename:
            print("\nSave scan results to file => " + self.output_filename)
            self.save_result(initial)
        print("\n\n"+self.Selected("[+]")+" RESULTS")
        for i in range(0,16):
            print("-",end="",flush=True)
            sleep(1/9)
        print("")
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
        print("\r" + " " * 24 + "\n[✓] All specified ports scanned!\n")
        print(self.Selected("[+]")+" SUMMARY\n----------------")
        print(self.Bluebg2(" * ")+" Found " + str(len(self.found_ports)) + " open port/s")
        self.save_result(
            "\nSCAN RESULTS\n----------------\n[+] Found " + str(len(self.found_ports)) + " open port/s\n\n")

        if len(self.found_ports) != 0:
            line = "[*] Ports open => "
            for port in self.found_ports:
                line += str(port[0]) + ","
            print(line[:-1])
            print("")
            self.save_result(line[:-1] + '\n\n')

            self.runNmap()

        else:
            print(self.Redbg(" ! ")+" No ports were found open!")

    # nmap function
    def runNmap(self):
        if self.nmap is not None:
            port_list = ""
            print("\n\n"+self.Selected("[+]")+" Time for the Nmap scan now!\n---------------------------------")

            # Setting up ports to scan
            if self.nmap_ports == 'discovered':
                for port_and_banner in self.found_ports:
                    port_list += str(port_and_banner[0]) + ','
                port_list = port_list[:-1]
            elif self.nmap_ports == 'all':
                port_list = self.port_range_display
            else:  # manual
                port_list = input("Enter comma-separated ports and/or hyphen-separated port ranges to scan: ")

            # Check if nmap is not installed
            try:
                nmap_check = Popen([self.nmap_path, '-V'], stdout=PIPE, stderr=PIPE, stdin=None)
                out, err = nmap_check.communicate()

            except FileNotFoundError:
                print(self.Redbg(" ! ") + " nmap could not be found\n\nYour nmap command would be:")
                print("[..] nmap -p " + port_list + ' ' + self.nmap + ' ' + self.addr, end="\n\n")
                exit(0)

            # Run nmap
            nmap_output = []
            if self.output_filename:
                if "." in self.output_filename:
                    nmap_filename = self.output_filename.replace(".","_nmap.")
                else:
                    nmap_filename = self.output_filename + '_nmap'
                nmap_output = ['-oN',nmap_filename]
            run = [self.nmap_path,'-p',port_list] + [args for args in self.nmap.split(" ")] + nmap_output + [self.addr]
            print("[+] Nmap => ",end="")
            for each in run:
                print(each + " ",end="")
            print("\n")
            np = Popen(run,stderr=STDOUT,stdout=PIPE,stdin=None)
            for line in iter(np.stdout.readline,b''):
                print(line.decode(),end="")

    # Thread function
    def scan_port(self, addr, port):
        client = socket(AF_INET, SOCK_STREAM)
        client.settimeout(self.timeout)
        port_and_banner = []

        try: # Try to connect
            client.connect((addr, port))
            port_and_banner.append(port)
            port_and_banner.append("No banner received!")
            self.found_ports.append(port_and_banner)
            try: # Try to receive response
                response = client.recv(1024)
                try: # Try decoding the response
                    if self.full_banner:
                        r = response.decode().strip()
                    else:
                        r = response.decode().split("\n")[0]
                except UnicodeDecodeError:
                    r = "Banner received but cannot decode"
                finally:
                    port_and_banner[1] = r
            except: # Try to send string and then receive response
                for try_num in range(0, self.max_tries + 1):
                    client.sendall(self.junk)
                    try: # Try to receive response of sent string
                        response = client.recv(1024)
                        try: # Try decoding the response
                            if self.full_banner:
                                r = response.decode().strip()
                            else:
                                r = response.decode().split("\n")[0]
                        except UnicodeDecodeError:
                            r = "Banner received but cannot decode"
                        port_and_banner[1] = r
                        break
                    except: # No response received
                        continue
            print("\r"+self.Greenbg(" ->")+" Found port " + str(port_and_banner[0]) + " -> " + port_and_banner[1])
            if self.full_banner:
                print("")

        except ConnectionRefusedError: # If connection got refused
            pass

        finally:
            client.close()
            self.threads_running -= 1
            return


# MAIN
parser = ArgumentParser(description="Dirty Portscanner simply scans the range of ports you supply and "
                                    "shows which one of them might be open, plus any banners if any. This "
                                    "it does by connecting to each specified port and checking if "
                                    "something comes back as a response. If it doesn't, a junk string "
                                    "is sent to the port and then it is checked again if there's any "
                                    "response. This is repeated for a specified number of times to probe "
                                    "the port till specified timeout.",
                        add_help=True, epilog="Author: CaptainWoof | "
                                              "Twitter: @realCaptainWoof")
parser.add_argument("-a", "--address", action='store', type=str, required=True, help="The destination host to probe")
parser.add_argument("-p", "--port-range", action='store', type=str, required=True, help="The ports to probe; separate "
                                                                                        "ports by a comma ',', ranges by "
                                                                                        "a hyphen '-'; Example: 1-1000,3289,4444,8000-9000...")
parser.add_argument("-t", "--threads", action="store", type=int, required=False, default=10, help="The maximum number "
                                                                                                  "of concurrent threads "
                                                                                                  "to use; default is 10;"
                                                                                                  " INCREASE FOR SPEED!")
parser.add_argument("-m", "--max-tries", action='store', type=int, required=False, default=3, help="Maximum number of "
                                                                                                   "retries for probing "
                                                                                                   "each port: default is 3")
parser.add_argument("-u", "--timeout", action='store', type=float, required=False, default=3.0,
                    help="Maximum number of "
                         "seconds to wait for each "
                         "probe's response; default is "
                         "3 seconds")

junk_group = parser.add_mutually_exclusive_group()
junk_group.add_argument('-j',"--probe-string",action='store',type=str,required=False,default="AAAAAAAAAAAAAAAAAAA\r\n\r\n"
                    ,help="Choose a custom string to probe ports with; default: AAAAAAAAAAAAAAAAAAA\\r\\n\\r\\n")
junk_group.add_argument('-J',"--probe-string-file",action='store',type=str,required=False,default=None
                    ,help="Choose a custom file which contains strings to probe ports with; "
                          "provided file will be read in binary mode")
parser.add_argument("-o", "--output", action='store', type=str, required=False, default=False,
                    help="Save scan results to a file with specified filename; "
                         "using with nmap will output nmap results to another file with same name "
                         "but with '_nmap' as prefix")
parser.add_argument('--nmap', '-n', required=False, default=None, action='store', type=str,
                    help="Start an nmap scan automatically with specified nmap args here, enclosed within "
                         "double-inverted commas; nmap must be installed for this; also, don't "
                         "manually specify any ports here")
parser.add_argument("--nmap-ports", '-P', required=False, default='discovered', type=str, action='store',
                    choices=['discovered', 'all', 'manual'],
                    help="Specify ports to use in the nmap scan; 'discovered' automatically selects"
                         " only the discovered ports, 'all' uses your original port range/s,"
                         " 'manual' prompts you after scan for you to specify port ranges for the nmap scan;"
                         " default is 'discovered'")
parser.add_argument("--nmap-path",action='store',default='nmap',required=False,type=str,
                    help="Path to nmap; no need to use this option if nmap is in PATH "
                         "with the proper name")
parser.add_argument("--full-banner",'-b',action='store_true',default=False,required=False,
                    help="Display the full banner received instead of only the first line (default)")
argv = parser.parse_args()

port_scanner = DirtyPortScanner(argv.address, argv.port_range, argv.threads, argv.max_tries, argv.timeout,
                                argv.output, argv.nmap, argv.nmap_ports,argv.nmap_path,argv.probe_string,
                                argv.probe_string_file,argv.full_banner)
port_scanner.start()
