#!/usr/bin/env python3
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
          7.) provide documentation for design choices in the implementation.

    Solutions:
