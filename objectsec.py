#!/usr/bin/env python3

import random
import socket
import sys

PORT = 12000
HOST = ''
SIZE_DATA = 1024

"""
Proof-of-concept secure end-to-end communication using object security.

Written in: Python.
Crypto library used: PyCrypto.

    Instructions:
    -------------
        Implement a proof-of-concept secure connection for two parties that
        fulfills the following:
          1.) Utilizes the principle of object security.
          2.) Provide integrity, confidentiality and protect against replays.
          3.) Use UDP for data exchange.
          4.) Utilize forward security.
          5.) Be composed of two distinct phases, handshake + protected data
              exchange.
          6.) Actually works when tested.
          7.) Provide documentation for design choices in the implementation.

    Solutions:
    ----------
        1 : Security on application layer.
        2 : - Integrity - MAC.
            - Confidentiality - Encryption.
            - Replay - Sequence number for freshness.
        3 : Use UDP.
        4 : Use ephemeral keys for each session.
        5 : Use two distinct phases.
        6 : Make sure it works.
        7 : Document it.
"""

def super_secret_primes():
    """ Use sieve of Eratosthenes to generate all primes up to 10000. """
    primes_up_to = 1e5
    marked = [False]*primes_up_to
    primes = [1]
    for n in range(2,primes_up_to):
        if marked[n]:
            continue
        primes.append(n)
        mul_index = n
        while mul_index < primes_up_to-1:
            marked[mul_index] = True
            mul_index += n
    return primes

def generate_public_number():
    return random.integer(1,1e4)

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        print("Starting server on port {}, listening on UDP.".format(PORT))
        while True:
            try:
                message, address = s.recvfrom(SIZE_DATA)
                s.sendto(message, address)
            except KeyboardInterrupt as e:
                print("\nKeyboard interrupt received, closing down.")
                break

def client():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        message = b"HELLO WORLD!"
        address = ("127.0.0.1", PORT)

        s.sendto(message, address)
        data, server = s.recvfrom(SIZE_DATA)
        print("Data received: {}".format(str(data)))

def main(args):
    usage = "Usage: [python] {} --client/--server"
    if "--client" in args:
        client()
    elif "--server" in args:
        server()
    else:
        print(usage.format(__file__))

    #print(super_secret_primes())

if __name__ == "__main__":
    main(sys.argv[1:])
