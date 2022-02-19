# Xiaomi Mi Home Binary Protocol

The **Mi Home Binary Protocol** is used to configure & control smart home devices made by Xiaomi.

It is an encrypted, binary protocol, based on UDP. The designated port is 54321.

## Packet format

     0                   1                   2                   3   
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Magic number = 0x2131         | Packet Length (incl. header)  |
    |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    | Unknown1                                                      |
    |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    | Device ID ("did")                                             |
    |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    | Stamp                                                         |
    |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    | MD5 checksum                                                  |
    | ... or Device Token in response to the "Hello" packet         |
    |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
    | optional variable-sized data (encrypted)                      |
    |...............................................................|
    
                    Mi Home Binary Protocol header
           Note that one tick mark represents one bit position.
     
     Magic number: 16 bits
         Always 0x2131
         
     Packet length: 16 bits unsigned int
         Length in bytes of the whole packet, including the header.
      
     Unknown1: 32 bits
         This value is always 0,
         except in the "Hello" packet, when it's 0xFFFFFFFF
         
     Device ID: 32 bits
         Unique number. Possibly derived from the MAC address.
         except in the "Hello" packet, when it's 0xFFFFFFFF
 
     Stamp: 32 bit unsigned int
         continously increasing counter
         
     MD5 checksum:
         calculated for the whole packet including the MD5 field itself,
         which must be initialized with 0.
         
         In the special case of the response to the "Hello" packet,
         this field contains the 128-bit device token instead.
     
     optional variable-sized data:
         encrypted with AES-128: see below.
         length = packet_length - 0x20
          

## Initial handshake ("SmartConnect")

1. Client → Device

	This is what I call the "Hello packet". The client can send it as often as 
	they want and they will always get the same reply:
	
         0                   1                   2                   3   
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | 0x2131                        | 0x0020                        |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        | 0xffffffff                                                    |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        | 0xffffffff                                                    |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        | 0xffffffff                                                    |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        | 0xffffffffffffffffffffffffffffffff                            |
        |                                                               |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
      

2. Device → Client

         0                   1                   2                   3   
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | 0x2131                        | 0x0020                        |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        | 0x00000000                                                    |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        | 0x12345678                                                    |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        | Stamp                                                         |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
        | Token (128-bit)                                               |
        | All subsequent encryption is based on this number.            |
        |-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
       
	The 128-bit token is used to identify the device and, more importantly, to 
	encrypt all further communication.

*Update 2017-02-23:* Xiaomi updated the device firmwares and only 
uninitialized devices reveal their token now. 

## Encryption
The variable-sized data payload is encrypted with the Advanced Encryption 
Standard (AES). A 128-bit key and Initialization Vector are both derived from 
the Token as follows:

    Key = MD5(Token)
    IV  = MD5(Key + Token)
    
PKCS#7 padding is used prior to encryption.

The mode of operation is Cipher Block Chaining (CBC).

## Payloads
Most payloads are JSON commands, documented in the "Yeelight Inter-Operation 
Spec".

One critical exception is the transmission of the user's WiFi credentials:

    {
      'id': XXX, 
      'method': 'miIO.config_router',
      'params': {
        'ssid': 'WiFi network',
        'passwd': 'WiFi password',
        'uid': YYY
      }
    }

* `id` is a UNIX timestamp.
* `uid` identifies the device owner. The device will phone home and report this to Xiaomi.



## Appendix
### Authors
This document is part of the [OpenMiHome project](https://github.com/openmihome). Authors include:

 * Wolfgang Frisch ([GitHub](https://github.com/wfr))
 
### Links
 * [Wireshark](https://www.wireshark.org/)
 * [Xiaomi MAC addresses](http://hwaddress.com/company/xiaomi-communications-co-ltd)
 * [Yeelight Inter-Operation Spec PDF](http://www.yeelight.com/download/Yeelight_Inter-Operation_Spec.pdf)
 * [PKCS#7 padding](https://en.wikipedia.org/wiki/Padding_\(cryptography\)#PKCS7)

