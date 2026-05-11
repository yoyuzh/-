import socket
import unittest

from start import choose_port, port_is_available


class StartPortTests(unittest.TestCase):
    def bind_first_available_port(self) -> socket.socket:
        for port in range(18000, 18100):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(("127.0.0.1", port))
                sock.listen()
                return sock
            except OSError:
                sock.close()
        self.fail("No available test port found")

    def test_occupied_port_is_not_reported_available(self) -> None:
        with self.bind_first_available_port() as sock:
            occupied_port = sock.getsockname()[1]

            self.assertFalse(port_is_available("127.0.0.1", occupied_port))

    def test_choose_port_skips_occupied_preferred_port(self) -> None:
        with self.bind_first_available_port() as sock:
            occupied_port = sock.getsockname()[1]

            chosen_port = choose_port("127.0.0.1", occupied_port)

        self.assertNotEqual(chosen_port, occupied_port)
        self.assertGreater(chosen_port, occupied_port)

    def test_choose_port_can_fail_strictly(self) -> None:
        with self.bind_first_available_port() as sock:
            occupied_port = sock.getsockname()[1]

            with self.assertRaises(SystemExit):
                choose_port("127.0.0.1", occupied_port, strict_port=True)


if __name__ == "__main__":
    unittest.main()
