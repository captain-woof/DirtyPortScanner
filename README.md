# DirtyPortScanner

### Introduction

Dirty Portscanner simply scans the range of ports you supply and shows which one of them might be open. This it does by connecting to each specified port and checking if something comes back as a response. If it doesn't, a junk string is sent to the port and then it is checked again if there's any response. This is repeated for a specified number of times to probe the port till specified timeout.

### Usage

```
usage: dirty_portscanner.py [-h] -a ADDRESS -p PORT_RANGE [-t THREADS] [-m MAX_TRIES] [-u TIMEOUT] [-b] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        The destination host to probe
  -p PORT_RANGE, --port-range PORT_RANGE
                        The ports to probe; separate ports by a comma (,) and ranges by a hyphen (-)
                        Example: 1-1000,3289,4444,8000-9000...
  -t THREADS, --threads THREADS
                        The maximum number of concurrent threads to use; default is 10
  -m MAX_TRIES, --max-tries MAX_TRIES
                        Maximum number of retries for probing each port: default is 3
  -u TIMEOUT, --timeout TIMEOUT
                        Maximum number of seconds to wait for each probe's response; default is 3
                        seconds
  -b, --banner          Display grabbed banner; non-default
  -o OUTPUT, --output OUTPUT
                        Save scan results to a file with specified filename
```

### Windows Executable
Generated with PyInstaller on Windows 7, so it should work on any version of Windows 7 and above.

### Author

Author: CaptainWoof

Twitter: [@realCaptainWoof](https://www.twitter.com/realCaptainWoof)

