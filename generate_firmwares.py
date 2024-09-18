#!/usr/bin/env python3
import os
import glob
import datetime
import argparse
import base64
import json
import hashlib
from pypush_gsa_icloud import icloud_login_mobileme, generate_anisette_headers
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
import zipfile
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def patch_firmware(hashed_adv):
    firmware_path = "dist/placemate_m1_base_firmware.bin"
    if not os.path.exists(firmware_path):
        raise FileNotFoundError("Firmware file not found")

    with open(firmware_path, 'rb') as f:
        firmware = f.read()

    pattern = b"OFFLINEFINDINGPUBLICKEYHERE!"
    public_key = base64.b64decode(hashed_adv)

    patched_firmware = firmware.replace(pattern, public_key)

    # with open("/tmp/firmware.bin", 'wb') as f:
    #    f.write(patched_firmware)

    return patched_firmware


def generate_dfu_package(hashed_adv, name):
    # First we create the patched firmware
    patched_firmware = patch_firmware(hashed_adv)

    # Now generate the initPacket
    init_packet_header = bytes([0x12, 0x8a, 0x01, 0x0a, 0x44, 0x08, 0x01, 0x12, 0x40])
    signed_init_packet = bytearray([0x08, 0x01, 0x10, 0x34, 0x1a, 0x02, 0x83, 0x02, 0x20, 0x00, 0x28,
                                    0x00, 0x30, 0x00, 0x38, 0xd8, 0x95, 0x03, 0x42, 0x24, 0x08, 0x03, 0x12, 0x20])

    # SHA256 of the patchedFirmware
    sha256_firmware = hashlib.sha256(patched_firmware).digest()

    # Add the SHA256 in reverse order
    signed_init_packet.extend(sha256_firmware[::-1])

    # Add fixed data
    signed_init_packet.extend([0x48, 0x00, 0x52, 0x04, 0x08, 0x01, 0x12, 0x00])

    # Load the private key
    with open("dist/private.key", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Sign the data
    signature = private_key.sign(
        signed_init_packet,
        ec.ECDSA(hashes.SHA256())
    )

    # Extract R & s from the signature
    r, s = decode_dss_signature(signature)

    # Add fixed data
    signed_init_packet.extend([0x10, 0x00, 0x1a, 0x40])

    # Add the signedData
    signed_init_packet.extend(r.to_bytes(32, byteorder='little'))
    signed_init_packet.extend(s.to_bytes(32, byteorder='little'))

    # Prepend the header
    final_init_packet = init_packet_header + signed_init_packet

    # Write the files
    with open("/tmp/initpacket.dat", 'wb') as f:
        f.write(final_init_packet)
    with open("/tmp/firmware.bin", 'wb') as f:
        f.write(patched_firmware)

    # Create the manifest
    manifest = """{
    "manifest": {
        "application": {
            "bin_file": "nrf52810_xxaa.bin",
            "dat_file": "nrf52810_xxaa.dat"
        }
    }
}"""
    manifest = manifest.replace("nrf52810_xxaa.bin", "firmware.bin")
    manifest = manifest.replace("nrf52810_xxaa.dat", "initpacket.dat")
    with open("/tmp/manifest.json", 'w') as f:
        f.write(manifest)

    # Create the zip file
    with zipfile.ZipFile(name+".zip", 'w') as zipf:
        zipf.write("/tmp/manifest.json", arcname="manifest.json")
        zipf.write("/tmp/initpacket.dat", arcname="initpacket.dat")
        zipf.write("/tmp/firmware.bin", arcname="firmware.bin")

    # Remove the temporary files
    os.remove("/tmp/manifest.json")
    os.remove("/tmp/initpacket.dat")
    os.remove("/tmp/firmware.bin")

    return final_init_packet


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--prefix', help='only generate for this prefix', default='')
    args = parser.parse_args()

    # Check that dist/private.key exists
    if not os.path.exists("dist/private.key"):
        print("dist/private.key not found")
        exit(1)

    names = {}
    for keyfile in glob.glob(os.path.dirname(os.path.realpath(__file__)) + '/' + args.prefix + '*.keys'):
        # read key files generated with generate_keys.py
        with open(keyfile) as f:
            hashed_adv = priv = ''
            name = os.path.basename(keyfile).replace('.keys', '')
            for line in f:
                key = line.rstrip('\n').split(': ')
                if key[0] == 'Advertisement key':
                    hashed_adv = key[1]

            if hashed_adv:
                names[hashed_adv] = name
            else:
                print(f"Couldn't find adv key in {keyfile}")

    for hashed_adv in names:
        print(f"Generating firmware for {names[hashed_adv]}")

        # generate firmware
        generate_dfu_package(hashed_adv, names[hashed_adv])
