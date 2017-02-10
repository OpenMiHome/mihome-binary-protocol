# Xiaomi's MiHome Binary protocol

## Summary 
Xiaomi is a manufacturer of "Smart Home" devices. These devices use an encrypted, binary protocol to communicate 
with the official "Mi Home" app.

This repository documents this protocol, henceforth referred to as "mihobi", 
and contains exemplary source code to parse and analyze the protocol's flawed 
encryption scheme.

It has been tested with the Xiaomi Yeelight RGBW smart bulb.

![Yeelight bulb](img/yeelight-exploded.jpg)

## Motivation
The main goal of this project is to remove the dependence on proprietary software 
for controlling _Xiaomi MiHome_ devices. Until now there was no way to 
initialize a newly purchased device without running the proprietary Android 
app that demands extensive privileges and phones home to the manufacturer.

As of 2017-02-10, these devices **broadcast the user's WiFi credentials with 
pseudo-encryption that can be easily cracked by any passive listener**.

## Contents

[doc/PROTOCOL.md](doc/PROTOCOL.md)

### pcap-ng decryptor

The program  `pcap-decrypt.py` recovers the protocol from pcap-ng dumps. It 
attempts to decrypt the contents.

#### Dependencies
 * tshark, the console version of Wireshark
 
        apt-get install tshark
 * Python 3.5+
 * [PyShark](https://kiminewt.github.io/pyshark/), Python wrapper for tshark.
 
       pip3 install pyshark
 * [cryptography](https://cryptography.io/), a Python library which exposes cryptographic recipes and primitives.
 
       pip3 install cryptography
       
#### Usage
    ./pcap-decrypt.py example.pcapng.gz
    
#### Example output

    ### 192.168.13.2 (xx:xx:xx:xx:xx:xx) => 192.168.13.1 (yy:yy:yy:yy:yy:yy)
    META: Hello

    ### 192.168.13.1 (yy:yy:yy:yy:yy:yy) => 192.168.13.2 (xx:xx:xx:xx:xx:xx)
    META: device yy:yy:yy:yy:yy:yy has token: abcdef1234567890abcdef1234567890

    ### 192.168.13.2 (xx:xx:xx:xx:xx:xx) => 192.168.13.1 (yy:yy:yy:yy:yy:yy)
    DECRYPTED: {"id":1234567890,"method":"miIO.config_router",
    "params":{"ssid":"WiFi name","passwd":"WiFi password","uid":987654321}}

    ### 192.168.13.1 (yy:yy:yy:yy:yy:yy) => 192.168.13.2 (xx:xx:xx:xx:xx:xx)
    DECRYPTED: {"result":["ok"],"id":1234567890}

 

## Appendix
### Legal

Xiaomi is a registered trademark and service mark of Xiaomi Inc., which is not 
affiliated with the maker of this program and does not endorse, service or 
warrant the functionality of this product.

### Author

The source code and documention in this repository

(c) 2016-2017 Wolfgang Frisch

Licensed under the GPLv3.

