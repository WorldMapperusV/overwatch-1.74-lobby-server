"""A game-server process that only records the UDP packets sent to it.

It does not speak the Overwatch game protocol, which is still unknown, and it is not a playable
world. Run as `py -m ow174.matches.instance`. The manager in runtime.py reads its state.json.
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def write_state(path, value):
    """Write state.json through a temporary file, so a reader never sees half a file."""
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def _stop_when_parent_closes_stdin(stop: threading.Event) -> None:
    """The manager holds our stdin open. When it closes it, or dies, we shut down."""

    def wait_for_eof():
        sys.stdin.buffer.read()
        stop.set()

    threading.Thread(target=wait_for_eof, daemon=True).start()


def _initial_state(directory, host, port, player, mode, activity) -> dict:
    return {
        "id": directory.name,
        "pid": os.getpid(),
        "player": player,
        "mode": f"0x{mode:016X}",
        "host": host,
        "port": port,
        "activity": activity,
        "state": "starting",
        "protocol_ready": False,
        "packets_received": 0,
        "bytes_received": 0,
        "started_at": time.time(),
        "last_packet_at": None,
        "authenticated_packets": 0,
        "handshake_responses": 0,
    }


def _nonce(base: bytes, counter: int) -> bytes:
    return base + counter.to_bytes(4, "little")


def _verify_control_frame(data: bytes, nonce_base: bytes, key: bytes) -> bool:
    if len(data) != 34 or data[0x21] != 0xAD:
        return False
    counter = int.from_bytes(data[0x10:0x14], "little")
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(_nonce(nonce_base, counter), data[:12], min_tag_length=12),
    ).decryptor()
    decryptor.authenticate_additional_data(data[12:34])
    try:
        decryptor.finalize()
    except InvalidTag:
        return False
    return True


def _control_frame(nonce_base: bytes, key: bytes, counter: int, flags: int) -> bytes:
    # The zero-payload 1.74 transport control frame is 22 clear/AAD bytes plus a 12-byte GCM tag.
    header = (
        bytes.fromhex("10 00 00 F0")
        + counter.to_bytes(4, "little")
        + bytes(12)
        + bytes((flags, 0xAD))
    )
    encryptor = Cipher(algorithms.AES(key), modes.GCM(_nonce(nonce_base, counter))).encryptor()
    encryptor.authenticate_additional_data(header)
    ciphertext = encryptor.finalize()
    if ciphertext:
        raise AssertionError("zero-payload control frame unexpectedly produced ciphertext")
    return encryptor.tag[:12] + header


def _record_packets(
    sock,
    stop,
    state,
    state_path,
    log_path,
    client_tx_nonce,
    client_tx_key,
    client_rx_nonce,
    client_rx_key,
) -> None:
    server_counter = 0
    with log_path.open("a", encoding="utf-8", buffering=1) as log:
        while not stop.is_set():
            try:
                data, peer = sock.recvfrom(65535)
            except TimeoutError:
                continue
            state["packets_received"] += 1
            state["bytes_received"] += len(data)
            state["last_packet_at"] = time.time()
            entry = {
                "time": state["last_packet_at"],
                "peer": list(peer),
                "bytes": len(data),
                "hex": data.hex(),
            }

            if len(data) == 34 and data[0x21] == 0xAD:
                entry["control_flags"] = data[0x20]
                entry["counter"] = int.from_bytes(data[0x10:0x14], "little")
                authenticated = _verify_control_frame(data, client_tx_nonce, client_tx_key)
                entry["authenticated"] = authenticated
                if authenticated:
                    state["authenticated_packets"] += 1
                    if data[0x20] & 0x03 == 0x01:
                        response = _control_frame(
                            client_rx_nonce, client_rx_key, server_counter, 0x03
                        )
                        sock.sendto(response, peer)
                        entry["response_flags"] = 0x03
                        entry["response_counter"] = server_counter
                        entry["response_hex"] = response.hex()
                        server_counter = (server_counter + 1) & 0xFFFFFFFF
                        state["handshake_responses"] += 1
                    elif data[0x20] & 0x03 == 0x02:
                        state["protocol_ready"] = True
                        state["state"] = "transport-ready"
                        entry["handshake"] = "client-final-ack"
                else:
                    entry["auth_error"] = "AES-GCM tag rejected"

            log.write(json.dumps(entry) + "\n")
            write_state(state_path, state)


def run(
    directory,
    host,
    port,
    player,
    mode,
    control_stdin=False,
    activity="queue",
    client_tx_nonce=b"",
    client_tx_key=b"",
    client_rx_nonce=b"",
    client_rx_key=b"",
):
    directory.mkdir(parents=True, exist_ok=True)
    state_path = directory / "state.json"
    stop = threading.Event()
    if control_stdin:
        _stop_when_parent_closes_stdin(stop)
    state = _initial_state(directory, host, port, player, mode, activity)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((host, port))
        except OSError as error:
            state.update(state="failed", error=str(error))
            write_state(state_path, state)
            return 1
        state.update(port=sock.getsockname()[1], state="listening")
        write_state(state_path, state)
        sock.settimeout(0.2)  # wake up regularly to check the stop flag
        _record_packets(
            sock,
            stop,
            state,
            state_path,
            directory / "packets.jsonl",
            client_tx_nonce,
            client_tx_key,
            client_rx_nonce,
            client_rx_key,
        )
    state.update(state="stopped", stopped_at=time.time())
    write_state(state_path, state)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--player", required=True)
    parser.add_argument("--mode", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--control-stdin", action="store_true")
    parser.add_argument("--activity", choices=("queue", "practice"), default="queue")
    parser.add_argument("--client-tx-nonce", required=True)
    parser.add_argument("--client-tx-key", required=True)
    parser.add_argument("--client-rx-nonce", required=True)
    parser.add_argument("--client-rx-key", required=True)
    args = parser.parse_args()
    return run(
        args.directory,
        args.host,
        args.port,
        args.player,
        args.mode,
        args.control_stdin,
        args.activity,
        bytes.fromhex(args.client_tx_nonce),
        bytes.fromhex(args.client_tx_key),
        bytes.fromhex(args.client_rx_nonce),
        bytes.fromhex(args.client_rx_key),
    )


if __name__ == "__main__":
    raise SystemExit(main())
