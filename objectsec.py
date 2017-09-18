#!/usr/bin/env python3

import random
import socket
import sys

PORT = 12000
HOST = ''
SIZE_DATA = 1024

TYPE_INITIATE = "INITIATE"
TYPE_ANSWER = "ANSWER"

CMD_SHAKE = "SHAKE"
CMD_SHARED = "SHARED"

DELIM_DATA = ','
ENCODING='utf-8'


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

def get_prime():
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
        - Initiate -- Send public numbers p, g and g^a mod p to client(s),
                      return own secret a.
        - Answer -- Send computation g^y mod p back.
    """
    if shake_type == TYPE_INITIATE:
        p = get_prime() # Public (prime) modulus.
        g = get_prime() # Public (prime) base.
        a = get_prime() # Server private key.
        g_raised_to_a_mod_p = g**a % p
        send_data(socket, [p, g, g_raised_to_a_mod_p], address)
        print("Sending p: {}, g: {}, g^mod p: {}".format(p, g,
            g_raised_to_a_mod_p))
        print("Keeping {} as own secret.".format(a))
        return a

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        print("Starting server on port {}, listening on UDP.".format(PORT))
        while True:
            try:
                tokens, address = get_data(s)
                command = tokens.pop(0)
                if command == CMD_SHAKE:
                    my_secret = handshake(TYPE_INITIATE, s, address)
                elif command == CMD_SHARED:
                    print("SHARE")
            except KeyboardInterrupt as e:
                print("\nKeyboard interrupt received, closing down.")
                break

def send_data(socket, data, address):
    if type(data) != list:
        data = [data]
    data = [str(item) for item in data]
    data = bytes(",".join(data), ENCODING)
    socket.sendto(data, address)


def get_data(socket):
    data, sender = socket.recvfrom(SIZE_DATA)
    str_data = data.decode(ENCODING)
    str_tokens = [token.strip() for token in str_data.split(DELIM_DATA)]
    return str_tokens, sender


def client():

    address = ("127.0.0.1", PORT)
    shared_rsa_secret = ""

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

        "Initiate handshake."
        send_data(s, CMD_SHAKE, address)
        data_tokens, server = get_data(s)
        # Get Diffie-Hellman primitives from server.
        p, g, g_raised_to_a_mod_p = [int(token) for token in data_tokens]
        print("Received p: {}, g: {}, g^a mod p: {}".format(p, g, g_raised_to_a_mod_p))
        b = get_prime() # Client private key.
        g_raised_to_b_mod_p = g**b % p
        # Send computed intermediary to server.
        send_data(s, [CMD_SHARED,g_raised_to_b_mod_p], server)
        # Receive computed intermediary from server.
        data, server = s.recvfrom(SIZE_DATA)
        command, value = get_data(s)
        if command == CMD_SHARED:
            shared_rsa_secret = int(value)**b % p
        print("Received {} from sever, computed shared secret: {}".format(
            shared_rsa_secret))




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
