# Tiny Wifi Sniffer

This repository contains an example of how to use the Python Scapy library to perform packet capture on a Wi-Fi network.

The program uses two threads of execution: one for packet capture and another to perform a deauthentication function. The program also uses Python's threading module to handle the SIGINT (Control + C) signal interruption and properly close the threads.

## Installation

To use this program, you will need to have Python 3 and the Scapy library installed on your system.

To install Scapy, you can use pip (the Python package manager) by running the following command in your terminal:

```
pip install scapy

```

## Usage

Before running the program, make sure to connect your Wi-Fi network interface to a Wi-Fi network.

To run the program, open a terminal and navigate to the directory where the `wifi_scanner.py` file is located. Then, run the following command in the terminal:

```
python wifi_scanner.py <interface>

```

Where `<interface>` is the name of the Wi-Fi network interface that the program will use. If left blank, the program will use the "wlan0" interface by default.

The program will start capturing packets on the Wi-Fi network and print them to the console.

You can also adjust the following parameters to customize the program:

- `RAM_THRESHOLD`: the RAM usage threshold in bytes that will trigger a pause in packet capture to prevent memory errors (default is 1000000).
- `deauth_thread`: the thread that runs the deauthentication function (default is a daemon thread that runs in the background).
- `sniffer_thread`: the thread that runs the packet capture (default is a daemon thread that runs in the background).

## Limitations

Note that the use of the deauthentication function can disrupt the connection of devices on the Wi-Fi network and cause them to lose connection to the network. Therefore, it is recommended to be careful when using the deauthentication function while simultaneously performing packet capture, and consider stopping the deauthentication function before analyzing the captured packets, to avoid disrupting the connection of devices on the network.

This program is provided for educational purposes only and should not be used for illegal or malicious activities.

### The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.