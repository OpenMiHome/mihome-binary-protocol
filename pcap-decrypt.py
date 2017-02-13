#!/usr/bin/env python3
"""Decipher Xiaomi's MiHome local binary protocol from Wireshark / pcap-ng
captures.

(c) 2017 Wolfgang Frisch
https://github.com/ximihobi

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import sys
import argparse
import json
import pprint
import ipaddress
try:
    # https://github.com/KimiNewt/pyshark
    import pyshark
except ImportError:
    print("ERROR: can't import pyshark. pip3 install pyshark", file=sys.stderr)
    sys.exit(1)
import miio


def get_macs(packet):
    """Get the MAC addresses from a PyShark packet.
    Returns (source MAC, destination MAC)
    """
    if "eth" in packet:
        return (packet.eth.src, packet.eth.dst)
    elif "wlan" in packet:
        return (packet.wlan.ta, packet.wlan.addr)
    raise Exception("Cannot find a MAC address.")


parser = argparse.ArgumentParser(
    description=(
        "Decipher Xiaomi's MiHome local binary protocol from "
        "Wireshark / pcap-ng captures"))
parser.add_argument("pcapfile", type=str, help="path to pcapng dump")
parser.add_argument("--print-headers", action='store_true')
parser.add_argument("--print-raw", action='store_true')
args = parser.parse_args()


XIAOMI_MAC = "f0:b4:29"
cap = pyshark.FileCapture(
    args.pcapfile,
    display_filter=(
        "(wlan.addr[0:3]=={0} || eth.addr[0:3]=={0}) "
        "&& udp.port == 54321".format(XIAOMI_MAC)))

device_token = {}  # type: Dict[str, bytes]

for packet in cap:
    mac_src, mac_dst = get_macs(packet)
    incoming = mac_src.startswith(XIAOMI_MAC)
    outgoing = not incoming
    if not "data" in packet:
        continue
    packet.data.raw_mode = True
    data = bytearray.fromhex(packet.data.data)
    mp = miio.MiioPacket()
    mp.read(data)

    print("\n### {0} ({1}) => {2} ({3})".format(
        packet.ip.src, mac_src, packet.ip.dst, mac_dst))
    if args.print_raw:
        print("RAW: %s" % packet.data.data)
    if args.print_headers:
        print("HEADER:")
        miio.print_head(data)

    if not ipaddress.ip_address(packet.ip.src).is_private \
        or not ipaddress.ip_address(packet.ip.dst).is_private:
        print("NOT IMPLEMENTED: packet to/from Xiaomi Cloud")
        continue

    decrypted = None       
    if incoming:
        if len(mp.data) == 0:
            token = mp.md5
            device_token[mac_src] = token
            print("META: device {0} has token: {1}".format(mac_src, token.hex()))
        elif mac_src in device_token:
            decrypted = miio.decrypt(device_token[mac_src], data)
    elif outgoing:
        if mp.md5 == b"\xff" * 16:
            print("META: Hello")
        elif mac_dst in device_token:
            decrypted = miio.decrypt(device_token[mac_dst], data)
    if decrypted:
        print("DECRYPTED: %s" % decrypted.decode('UTF-8'))

# vim:set expandtab tabstop=4 shiftwidth=4 softtabstop=4 nowrap:
