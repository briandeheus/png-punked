#!/usr/bin/python3.9

import binascii
import struct
import argparse
import typing
import os

CHUNK_TYPE_END = "IEND"
CHUNK_TYPE_PUNK = "puNk"
MAX_BYTES = 2147483647
MODE_INJECT = "inject"
MODE_EXTRACT = "extract"
MODE_LIST = "list"
MODES = [MODE_LIST, MODE_INJECT, MODE_EXTRACT]
SIGNATURE_BYTES = 8
BYTES_IN_KB = 2014


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def bytes_to_utf(b: bytes) -> str:
    return b.decode()


def bytes_to_int(b: bytes) -> int:
    return int(bytes_to_hex(b=b), 16)


def read_bytes(f: typing.IO, byte_count: int) -> bytes:
    return f.read(byte_count)


def rewind_bytes(f: typing.IO, byte_count):
    f.seek(f.tell() - byte_count)


def get_file_length(f: typing.IO) -> int:
    f.seek(0, os.SEEK_END)
    file_length = f.tell()
    f.seek(0)

    return file_length


def read_chunk(f: typing.IO) -> list[bytes, bytes, bytes, bytes]:
    chunk_size = read_bytes(f, 4)
    chunk_type = read_bytes(f, 4)
    chunk_content = read_bytes(f, bytes_to_int(chunk_size))
    chunk_crc = read_bytes(f, 4)

    return [chunk_size, chunk_type, chunk_content, chunk_crc]


def inject_punk_chunk(f: typing.IO, content: bytes):
    chunk_size = len(content)

    if chunk_size > MAX_BYTES:
        raise ValueError(f"Cannot inject more than {MAX_BYTES} bytes")

    print(f"Injecting puNK chunk {chunk_size / BYTES_IN_KB} kb")

    # Create a byte array to store our chunk data in.
    tmp_bytes = bytearray()
    # First write the chunk type
    tmp_bytes.extend(CHUNK_TYPE_PUNK.encode())
    # Now write the bytes of whatever we're trying to hide
    tmp_bytes.extend(content)

    # Write the chunk size
    f.write(bytearray(struct.pack("!i", chunk_size)))

    # And the content
    f.write(tmp_bytes)

    crc = binascii.crc32(tmp_bytes)
    crc_bytes = crc.to_bytes(4, "big")
    print("Chunk CRC", bytes_to_hex(crc_bytes))
    f.write(crc_bytes)

    print("Chunk injected!")


def handle_list(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input")
    args = parser.parse_args()

    with open(args.input, "rb") as input_file:

        input_file_length = get_file_length(input_file)
        input_file.read(SIGNATURE_BYTES)

        while True:
            chunk_size, chunk_type, chunk_content, chunk_crc = read_chunk(input_file)
            chunk_type_str = bytes_to_utf(chunk_type)
            print(f"Chunk {chunk_type_str}, {bytes_to_int(chunk_size)} bytes")

            if input_file.tell() >= input_file_length:
                return


def handle_inject(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("content")
    args = parser.parse_args()

    with open(args.input, "rb") as input_file, open(
            args.output, "wb"
    ) as output_file, open(args.content, "rb") as content_file:

        input_file_length = get_file_length(input_file)
        output_file.write(input_file.read(SIGNATURE_BYTES))

        while True:
            chunk_size, chunk_type, chunk_content, chunk_crc = read_chunk(input_file)
            chunk_type_str = bytes_to_utf(chunk_type)
            print(f"Chunk {chunk_type_str}, {bytes_to_int(chunk_size)} bytes")

            if chunk_type_str == CHUNK_TYPE_END:
                inject_punk_chunk(output_file, content_file.read())

            output_file.write(chunk_size)
            output_file.write(chunk_type)
            output_file.write(chunk_content)
            output_file.write(chunk_crc)

            if input_file.tell() >= input_file_length:
                return


def handle_extract(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()

    print("Attempting to extract punked data from", args.input)

    with open(args.input, "rb") as input_file, open(
            args.output, "wb"
    ) as output_file:

        input_file_length = get_file_length(input_file)
        input_file.read(SIGNATURE_BYTES)

        while True:
            chunk_size, chunk_type, chunk_content, chunk_crc = read_chunk(input_file)
            chunk_type_str = bytes_to_utf(chunk_type)

            if chunk_type_str == CHUNK_TYPE_PUNK:
                print("Found a punk chunk worth", bytes_to_int(chunk_size), "bytes")
                output_file.write(chunk_content)
                return

            if input_file.tell() >= input_file_length:
                return


def main():
    parser = argparse.ArgumentParser(
        description="Inject or extract arbitrary payloads from PNG images"
    )
    parser.add_argument("mode", choices=MODES)
    args, _ = parser.parse_known_args()

    if args.mode == MODE_LIST:
        handle_list(parser=parser)
    elif args.mode == MODE_EXTRACT:
        handle_extract(parser=parser)
    elif args.mode == MODE_INJECT:
        handle_inject(parser=parser)


if __name__ == "__main__":
    main()
