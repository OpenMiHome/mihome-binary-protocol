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


# https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf
# |grep -i xiaomi |sort |awk '{ print "\""$1"\","  }'
MAC_PREFIXES_XIAOMI = frozenset([
    "00:9E:C8", "0C:1D:AF", "10:2A:B3", "14:F6:5A", "18:59:36", "20:82:C0",
    "28:6C:07", "28:E3:1F", "34:80:B3", "34:CE:00", "38:A4:ED", "3C:BD:3E",
    "58:44:98", "64:09:80", "64:B4:73", "64:CC:2E", "68:DF:DD", "74:23:44",
    "74:51:BA", "78:02:F8", "7C:1D:D9", "8C:BE:BE", "98:FA:E3", "9C:99:A0",
    "A0:86:C6", "AC:C1:EE", "AC:F7:F3", "B0:E2:35", "C4:0B:CB", "C4:6A:B7",
    "D4:97:0B", "F0:B4:29", "F4:8B:32", "F8:A4:5F", "FC:64:BA"
])


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

cap = pyshark.FileCapture(
    args.pcapfile, display_filter=("udp.port == 54321"))

device_token = {}  # type: Dict[str, bytes]

for packet in cap:
    if "data" not in packet:
        continue
    if (not ipaddress.ip_address(packet.ip.src).is_private
            or not ipaddress.ip_address(packet.ip.dst).is_private):
        print("NOT IMPLEMENTED: packet to/from Xiaomi Cloud")
        continue

    mac_src, mac_dst = get_macs(packet)
    incoming = mac_src.upper()[0:8] in MAC_PREFIXES_XIAOMI
    outgoing = mac_dst.upper()[0:8] in MAC_PREFIXES_XIAOMI
    packet.data.raw_mode = True
    data = bytearray.fromhex(packet.data.data)
    mp = miio.MiioPacket()
    mp.read(data)

    print("\n### {0} => {1} ({2} => {3})".format(
        packet.ip.src, packet.ip.dst, mac_src, mac_dst))
    if args.print_raw:
        print("RAW: %s" % packet.data.data)
    if args.print_headers:
        print("HEADER:")
        miio.print_head(data)

    decrypted = None
    if incoming:
        if len(mp.data) == 0:
            token = mp.md5
            device_token[mac_src] = token
            print("META: device {0} has token: {1}".format(
                mac_src, token.hex()))
        elif mac_src in device_token:
            decrypted = miio.decrypt(device_token[mac_src], data)
    elif outgoing:
        if mp.md5 == b"\xff" * 16:
            print("META: Hello")
        elif mac_dst in device_token:
            decrypted = miio.decrypt(device_token[mac_dst], data)
    if decrypted:
        print(decrypted.decode('UTF-8'))

# vim:set expandtab tabstop=4 shiftwidth=4 softtabstop=4 nowrap:
