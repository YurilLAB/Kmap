#!/usr/bin/env python3
"""The SMB test peer must accept a request split at any TCP read boundary."""
import unittest
from unittest.mock import patch

from cve_map_contracts import SmbHandler, SMB_NEGOTIATE_REPLY


class Socket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []

    def settimeout(self, value):
        pass

    def recv(self, count):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > count:
            self.chunks.insert(0, chunk[count:])
        return chunk[:count]

    def sendall(self, value):
        self.sent.append(value)


class SmbFixtureTests(unittest.TestCase):
    def request(self, chunks):
        sock = Socket(chunks)
        SmbHandler(sock, ("127.0.0.1", 0), None)
        return sock.sent

    def test_every_fragment_boundary(self):
        payload = b"\xffSMBr" + bytes(48)
        frame = bytes([0]) + len(payload).to_bytes(3, "big") + payload
        self.assertEqual(self.request([frame]), [SMB_NEGOTIATE_REPLY])
        for split in range(1, len(frame)):
            with self.subTest(split=split):
                self.assertEqual(self.request([frame[:split], frame[split:]]), [SMB_NEGOTIATE_REPLY])
        self.assertEqual(self.request([bytes([c]) for c in frame]), [SMB_NEGOTIATE_REPLY])

    def test_incomplete_and_other_protocols(self):
        for chunks in ([b""], [b"\0\0"], [b"\0\0\0\x10", b"\xffSMB"],
                       [b"GET / HTTP/1.1\r\n\r\n"], [b"\0\0\x10\x01"]):
            with self.subTest(chunks=chunks):
                self.assertEqual(self.request(chunks), [])

    def test_request_has_an_overall_deadline(self):
        with patch("cve_map_contracts.time.monotonic", side_effect=[0, 0, 11]):
            self.assertEqual(self.request([b"\0\0\0\x05\xffSMBr"]), [])


if __name__ == "__main__":
    unittest.main()
