from __future__ import annotations

import argparse
import socket

import uvicorn


def port_is_available(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def choose_port(host: str, preferred_port: int, strict_port: bool = False) -> int:
    if port_is_available(host, preferred_port):
        return preferred_port
    if strict_port:
        raise SystemExit(f"Port {preferred_port} is already in use.")

    for port in range(preferred_port + 1, min(preferred_port + 21, 65536)):
        if port_is_available(host, port):
            return port
    raise SystemExit(f"No available port found from {preferred_port} to {preferred_port + 20}.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Start the scanner web application.")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8000, help="Preferred port, default: 8000")
    parser.add_argument(
        "--strict-port",
        action="store_true",
        help="Fail instead of choosing the next free port when the preferred port is busy.",
    )
    args = parser.parse_args()

    port = choose_port(args.host, args.port, strict_port=args.strict_port)
    if port != args.port:
        print(f"Port {args.port} is in use; using port {port} instead.")
    print(f"Open http://{args.host}:{port}")
    uvicorn.run("backend.main:app", host=args.host, port=port, reload=False)


if __name__ == "__main__":
    main()
