# DirtyPortScanner

### Introduction

DirtyPortScanner simply scans the range of ports you supply and shows which one of them might be open. This it does by connecting to each specified port, and checking if a connection is made, which indicates an open port. Any response (like a banner) is checked as well by sending desired strings to each port.

Also, you can directly invoke nmap with the results of DirtyPortScanner if you wish, along with your chosen nmap arguments. See usage below.

**The maximum number of concurrent threads is the maximum number of ports that will be scanned simultaneously, so crank it up to get amazing speeds. If very, very high number of threads crash the script, simply reduce this.**

### Usage

```
usage: dirty_port_scanner.py [-h] -a ADDRESS -p PORT_RANGE [-t THREADS] [-m MAX_TRIES]
                             [-u TIMEOUT] [-j PROBE_STRING | -J PROBE_STRING_FILE] [--banner]
                             [-o OUTPUT] [--nmap NMAP] [--nmap-ports {discovered,all,manual}]
                             [--nmap-path NMAP_PATH]

optional arguments:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        The destination host to probe
  -p PORT_RANGE, --port-range PORT_RANGE
                        The ports to probe; separate ports by a comma ',', ranges by a hyphen '-';
                        Example: 1-1000,3289,4444,8000-9000...
  -t THREADS, --threads THREADS
                        The maximum number of concurrent threads to use; default is 10; INCREASE
                        FOR SPEED!                                                                   
  -m MAX_TRIES, --max-tries MAX_TRIES                                                               
                        Maximum number of retries for probing each port: default is 3
  -u TIMEOUT, --timeout TIMEOUT
                        Maximum number of seconds to wait for each probe's response; default is 3
                        seconds
  -j PROBE_STRING, --probe-string PROBE_STRING
                        Choose a custom string to probe ports with; default:
                        AAAAAAAAAAAAAAAAAAA\r\n\r\n
  -J PROBE_STRING_FILE, --probe-string-file PROBE_STRING_FILE
                        Choose a custom file which contains strings to probe ports with; provided
                        file will be read in binary mode
  --banner, -b          Display grabbed banner; non-default
  -o OUTPUT, --output OUTPUT
                        Save scan results to a file with specified filename; using with nmap will
                        output nmap results to another file with same name but with '_nmap' as
                        prefix
  --nmap NMAP, -n NMAP  Start an nmap scan automatically with specified nmap args here, enclosed
                        within double-inverted commas; nmap must be installed for this; also,
                        don't manually specify any ports here
  --nmap-ports {discovered,all,manual}, -P {discovered,all,manual}
                        Specify ports to use in the nmap scan; 'discovered' automatically selects
                        only the discovered ports, 'all' uses your original port range/s, 'manual'
                        prompts you after scan for you to specify port ranges for the nmap scan;
                        default is 'discovered'
  --nmap-path NMAP_PATH
                        Path to nmap; no need to use this option if nmap is in PATH with the
                        proper name
```

### Windows Executable
Generated with PyInstaller on Windows 7, so it should work on any version of Windows 7 and above.

### Author

Author: CaptainWoof

Twitter: [@realCaptainWoof](https://www.twitter.com/realCaptainWoof)

