#!/usr/bin/env python3

import random
import socket
import sys

PORT = 12000
HOST = ''
SIZE_DATA = 1024

TYPE_INITIATE = "INITIATE"
TYPE_ANSWER = "ANSWER"

CMD_SHAKE = b"SHAKE"
DELIM_DATA = ','

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


def generate_public_number():
    """ Return public number for Diffie-Hellman. """
    return random.randint(1,1e4)


def generate_private_number():
    """ Return secret number for Diffie-Hellman. """

    def super_secret_primes():
        """ Use sieve of Eratosthenes to generate all primes up to 10000. """
        primes_up_to = int(1e5)
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

    return random.choice(super_secret_primes())

def handshake(shake_type, socket, address):
    """ Handshake routine with different types, used for key-exchange:
        - Initiate -- Send public numbers n, g and g^x mod n to client(s),
                      return own secret x.
        - Answer -- Send computation g^y mod n back.
    """
    if shake_type == TYPE_INITIATE:
        n = generate_public_number()
        g = generate_public_number()
        x = generate_private_number()
        g_raised_to_x_mod_n = g**x % n
        response = ",".join([str(x) for x in [n, g, g_raised_to_x_mod_n]])
        socket.sendto(bytes(response, 'utf-8'), address)
        print("Sending n: {}, g: {}, g^mod n: {}".format(n, g,
            g_raised_to_x_mod_n))
        return x

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        print("Starting server on port {}, listening on UDP.".format(PORT))
        while True:
            try:
                message, address = s.recvfrom(SIZE_DATA)
                if message == CMD_SHAKE:
                    my_secret = handshake(TYPE_INITIATE, s, address)
            except KeyboardInterrupt as e:
                print("\nKeyboard interrupt received, closing down.")
                break


def client():

    address = ("127.0.0.1", PORT)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        "Initiate handshake."
        s.sendto(CMD_SHAKE, address)
        data, server = s.recvfrom(SIZE_DATA)
        n, g, g_raised_to_x_mod_n = [int(num.strip()) for num in
                data.decode('utf-8').split(DELIM_DATA)]
        print("Received n: {}, g: {}, g^x mod n: {}".format(n, g, g_raised_to_x_mod_n))


def main(args):
    usage = "Usage: [python] {} --client/--server"
    if "--client" in args:
        client()
    elif "--server" in args:
        server()
    else:
        print(usage.format(__file__))


if __name__ == "__main__":
    main(sys.argv[1:])
