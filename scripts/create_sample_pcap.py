from pathlib import Path


def main() -> None:
    output_path = Path("samples/manual/empty.pcap")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Little-endian PCAP global header, Ethernet link type, with zero packets.
    content = bytes.fromhex(
        "d4c3b2a1"  # magic
        "0200"      # major version
        "0400"      # minor version
        "00000000"  # timezone correction
        "00000000"  # timestamp accuracy
        "ffff0000"  # snapshot length: 65535
        "01000000"  # link type: Ethernet
    )
    output_path.write_bytes(content)
    print(output_path.resolve())


if __name__ == "__main__":
    main()

