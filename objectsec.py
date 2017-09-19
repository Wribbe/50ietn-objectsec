#!/usr/bin/env python3

import random
import socket
import sys

from Crypto import Random

from Crypto.Cipher import AES
from Crypto.Hash import HMAC

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
        return p, g, g_raised_to_a_mod_p, a

def send_data(socket, data, address, key="", poison="",
        poison_message=False):
    if type(data) != list:
        data = [data]
    data = [str(item) for item in data]
    if key:
        # Generate MAC and prefix to data.
        mac = generate_mac(key, data)
        if poison == "MAC": # Remove first element of mac.
            mac = mac[1:]
        elif poison == "DATA_PLAIN": # Remove first element in first data.
            data[0] = data[0][1:]
        # Prepend MAC to data.
        data = [mac] + data
    data = bytes(",".join(data), ENCODING)
    if key: # Encrypt data.
        data = encrypt(key, data)
        if poison == "DATA_ENCRYPTED":
            # Remove last encrypted token.
            data = data[:len(data)-1]
    socket.sendto(data, address)

def get_data(socket, key=""):
    data, sender = socket.recvfrom(SIZE_DATA)
    if key:
        print("Received encrypted data:", data)
        data = decrypt(key, data)
    str_data = data.decode(ENCODING)
    str_tokens = [token.strip() for token in str_data.split(DELIM_DATA)]
    if key:
        print("Checking MAC..")
        recieved_mac = str_tokens.pop(0)
        calculated_mac = generate_mac(key, str_tokens)
        if recieved_mac == calculated_mac:
            print("MAC checks out, integrity of data is ok!")
        else:
            print("MAC did not match, integrity of data can not be verified!")
    return str_tokens, sender

def encrypt(key, message):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return iv + cipher.encrypt(message)

def decrypt(key, message):
    block_size = AES.block_size
    iv = message[:block_size]
    message = message[block_size:]

    cipher = AES.new(key, AES.MODE_CFB, iv)
    return cipher.decrypt(message)

def calculate_shared_secret(computed_primitive, own_secret, public_mod):
    secret_length = 16
    shared_secret = computed_primitive**own_secret % public_mod
    # Make sure it has length secret_length, concatenate as string and slice.
    shared_secret = (str(shared_secret)*10)[:secret_length]
    # Convert back to bytes and return.
    return bytes(shared_secret, ENCODING)

def generate_mac(key, message):
    message = bytes(str(message), ENCODING)
    hmac = HMAC.new(key)
    hmac.update(message)
    # Return printable MAC.
    return hmac.hexdigest()

def server():

    p = ""
    g = ""
    a = ""
    g_raised_to_a_mod_p = ""
    shared_rsa_secret = ""

    def parse_commands():
        nonlocal p, g, a, g_raised_to_a_mod_p, shared_rsa_secret
        tokens, address = get_data(s, key=shared_rsa_secret)
        command = tokens[0]
        if command == CMD_SHAKE:
            # Remove command.
            tokens.pop(0)
            # Get primitives.
            primitives = handshake(TYPE_INITIATE, s, address)
            # Unpack primitives.
            p, g, g_raised_to_a_mod_p, a = primitives
        elif command == CMD_SHARED:
            # Remove command.
            tokens.pop(0)
            g_raised_to_b_mod_p = int(tokens[0])
            shared_rsa_secret = calculate_shared_secret(g_raised_to_b_mod_p, a,
                    p)
            print("Have the shared secret: {}".format(shared_rsa_secret))
        else: # Message.
            print("Got message: {}".format(tokens))
        print()


    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        print("Starting server on port {}, listening on UDP.".format(PORT))
        while True:
            try:
                parse_commands()
            except KeyboardInterrupt as e:
                print("\nKeyboard interrupt received, closing down.")
                break

def client():

    address = ("127.0.0.1", PORT)
    shared_rsa_secret = ""

    def handshake(address):
        "Initiate handshake."
        send_data(s, CMD_SHAKE, address)
        data_tokens, server = get_data(s)
        # Get Diffie-Hellman primitives from server.
        p, g, g_raised_to_a_mod_p = [int(token) for token in data_tokens]
        print("Received p: {}, g: {}, g^a mod p: {}".format(p, g,
            g_raised_to_a_mod_p))
        b = get_prime() # Client private key.
        g_raised_to_b_mod_p = g**b % p
        # Send computed intermediary to server.
        send_data(s, [CMD_SHARED,g_raised_to_b_mod_p], server)
        # Calculate shared secret.
        shared_rsa_secret = calculate_shared_secret(g_raised_to_a_mod_p, b, p)
        return shared_rsa_secret

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

        shared_rsa_secret = handshake(address)
        print("Computed shared secret: {}".format(shared_rsa_secret))
        message_plaintext = "This is an encrypted message."
        print("Massage plain-text:", message_plaintext)
        send_data(s, message_plaintext, address, shared_rsa_secret)
        print()

        message_mac_poison = "Message with poisoned MAC."
        print("Sending message with poisoned MAC:", message_mac_poison)
        send_data(s, message_mac_poison, address, shared_rsa_secret,
                poison="MAC")
        print()

        message_ok_mac_bad_message = "!Defect message with ok MAC."
        print("Sending bad message with ok MAC:", message_ok_mac_bad_message)
        send_data(s, message_ok_mac_bad_message, address, shared_rsa_secret,
                poison="DATA_PLAIN")
        print()

        message_poisoned_encryption = "Ok message with ok MAC but damaged"+\
                                      " encryption!"
        print("Sending ok message with ok MAC:", message_poisoned_encryption)
        send_data(s, message_poisoned_encryption, address, shared_rsa_secret,
                poison="DATA_ENCRYPTED")
        print()

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
