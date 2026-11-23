import socket
import unittest
from email.message import Message
from unittest.mock import patch

from ghostsec_engine.search import PageFetchError, fetch_page

PUBLIC_IP = "93.184.216.34"


class FakeSocket:
    def __init__(self, address=PUBLIC_IP):
        self.address = address
        self.closed = False

    def getpeername(self):
        return (self.address, 80)

    def close(self):
        self.closed = True


class FakeResponse:
    def __init__(self, status=200, body=b"<html><body><h1>Public page</h1><script>bad()</script></body></html>", headers=None):
        self.status = status
        self.body = body
        self.headers_map = headers or {"Content-Length": str(len(body))}

    def getheader(self, name):
        return self.headers_map.get(name)

    @property
    def headers(self):
        message = Message()
        for key, value in self.headers_map.items():
            message[key] = value
        return message

    def read(self, size=-1):
        return self.body[:size]


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.sock = None
        self.requested = None
        self.closed = False

    def request(self, method, path, headers=None):
        self.requested = (method, path, headers)

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True
        if self.sock:
            self.sock.close()


def dns_record(address):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 80))


class SearchFetchTests(unittest.TestCase):
    def test_rejects_unsupported_schemes_and_embedded_credentials(self):
        for url in (
            "file:///etc/passwd",
            "ftp://example.com/file",
            "http://user:password@example.com/",
            "http://localhost/",
        ):
            with self.subTest(url=url), self.assertRaises(PageFetchError):
                fetch_page(url)

    def test_rejects_host_with_any_non_public_dns_answer(self):
        with patch(
            "ghostsec_engine.search.socket.getaddrinfo",
            return_value=[dns_record(PUBLIC_IP), dns_record("127.0.0.1")],
        ):
            with self.assertRaisesRegex(PageFetchError, "non-public"):
                fetch_page("http://example.test/")

    def test_pins_request_to_validated_public_ip_and_extracts_text(self):
        body = b"<html><body><h1>Public page</h1><script>bad()</script></body></html>"
        response = FakeResponse(body=body)
        connection = FakeConnection(response)
        sock = FakeSocket()
        with (
            patch("ghostsec_engine.search.socket.getaddrinfo", return_value=[dns_record(PUBLIC_IP)]) as resolver,
            patch("ghostsec_engine.search.socket.create_connection", return_value=sock) as connector,
            patch("ghostsec_engine.search.http.client.HTTPConnection", return_value=connection),
        ):
            result = fetch_page("http://example.test/article")
        self.assertEqual(result, "Public page")
        resolver.assert_called_once()
        connector.assert_called_once_with((PUBLIC_IP, 80), timeout=15)
        self.assertEqual(connection.requested[0:2], ("GET", "/article"))
        self.assertTrue(connection.closed)

    def test_redirect_is_rejected_without_following_it(self):
        response = FakeResponse(status=302, headers={"Location": "http://127.0.0.1/"})
        connection = FakeConnection(response)
        sock = FakeSocket()
        with (
            patch("ghostsec_engine.search.socket.getaddrinfo", return_value=[dns_record(PUBLIC_IP)]),
            patch("ghostsec_engine.search.socket.create_connection", return_value=sock),
            patch("ghostsec_engine.search.http.client.HTTPConnection", return_value=connection),
        ):
            with self.assertRaisesRegex(PageFetchError, "Redirects are not followed"):
                fetch_page("http://example.test/")

    def test_rejects_oversized_content_length(self):
        response = FakeResponse(headers={"Content-Length": str(3 * 1024 * 1024)})
        connection = FakeConnection(response)
        sock = FakeSocket()
        with (
            patch("ghostsec_engine.search.socket.getaddrinfo", return_value=[dns_record(PUBLIC_IP)]),
            patch("ghostsec_engine.search.socket.create_connection", return_value=sock),
            patch("ghostsec_engine.search.http.client.HTTPConnection", return_value=connection),
        ):
            with self.assertRaisesRegex(PageFetchError, "2 MiB"):
                fetch_page("http://example.test/")


if __name__ == "__main__":
    unittest.main()
