#!/usr/bin/python3

import datetime
import hashlib
import math
from Crypto.Cipher import AES
import sys
import re
from random import randbytes


class cipherbreaker:
    def __init__(self) -> None:
        self.pubkey = "-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtn1V6o52TqKaNGd11Opd\n02522R24QS/t8NYRMD3BB7f8O5pCZSfh7/zMM6PTPK8KvZcVndN0B0MqOHCAkSla\nUWO2JlJD0rLs7mFHL9f+sI3pl8QBpS/g/UmmzhCUz1Q3G+3HZLjIF7gaa7QlAx7I\nagKhwAbFH0n/HlJIZMcl6o0kk1KxDGvdoyhTM3yYaMFiiDRhpRMMmfAXObAAFAk5\nOiC6IZ7dFNADDUmy2CFle7HN1WsGMUYzf248N99IQDrwWN4MX2GXXQOwAiaCRrDp\nT/sV8X2oJhug5LnBQEGKdxUkIzG/m9/6xn27LDrNjQWvEimZEfl6c3LgHuBrwRt+\nlQIDAQAB\n-----END RSA PUBLIC KEY-----\n"

        date = datetime.datetime.utcnow()
        self.hours = date.hour
        self.n = 10 * math.floor(date.minute / 10)

        self.mode = "decrypt"

    def setMode(self, mode: str) -> None:
        self.mode = mode

    def setTimestamp(self, timestamp: str) -> None:
        timestamps = timestamp.split(":")
        self.hours = int(timestamps[0])
        self.n = 10 * math.floor(int(timestamps[1]) / 10)

    def setCipherText(self, cipherText: str) -> None:
        self.target = cipherText

    def setTarget(self, target: str) -> None:
        self.target = target.strip()

    def genKey2(self, hours: int, n: int) -> bytes:
        manKey = self.pubkey[:hours] + str(hours) + self.pubkey[hours:]
        manKey = (manKey[:n] + str(n) + manKey[n:]).encode()

        md5 = hashlib.md5(manKey).hexdigest()
        return md5.encode()

    def genKey(self) -> bytes:
        return self.genKey2(self.hours, self.n)

    def decrypt(self, key: bytes) -> str:
        if not hasattr(self, "cipherText"):
            print("Missing ciphertext")
            exit(0)

        iv = bytes.fromhex(self.target[:24])
        tag = bytes.fromhex(self.target[-32:])
        cipherText = bytes.fromhex(self.target[24:-32])

        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        plaintext = cipher.decrypt(cipherText)

        try:
            cipher.verify(tag)
            return (True, plaintext.decode())
        except ValueError:
            return (False, "")

    def encrypt(self, key: bytes) -> str:
        if not hasattr(self, "target"):
            print("Missing missing plaintext file")
            exit(0)

        iv = randbytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipherText, tag = cipher.encrypt_and_digest(self.target.encode())

        iv = iv.hex()
        cipherText = cipherText.hex()
        tag = tag.hex()

        return iv + cipherText + tag

    def run(self) -> str:
        if self.mode == "decrypt":
            result = self.decrypt(self.genKey())
            return result[1] if result[0] else "Wrong timestamp or broken ciphertext"
        elif self.mode == "encrypt":
            return self.encrypt(self.genKey())
        elif self.mode == "force":
            runs = 144
            hours = self.hours
            n = self.n
            result = (False, "")
            while not (runs == 0 or result[0]):
                key = self.genKey2(hours, n)
                result = self.decrypt(key)
                runs -= 1
                if n == 50:
                    n = 0
                    hours = (hours + 1) % 24
                else:
                    n += 10
            return (
                "{}\n{}:{}".format(result[1], hours, n)
                if result[0]
                else "No combination found"
            )
        else:
            print("No mode chosen")
            exit(0)


breaker = cipherbreaker()
i = 0
args = sys.argv
while i < len(args):
    if args[i] == "-e":
        breaker.setMode("encrypt")
    elif args[i] == "-t":
        if len(args) == i + 1:
            print("Missing agrument HH:mm")
            exit(0)
        timestamp = args[i + 1]
        timestamp = re.search("^[0-9]{1,2}:[0-9]{1,2}$", timestamp)
        if not timestamp:
            print(
                "Broken argument -t "
                + args[i + 1]
                + "  Must match ^[0-9]{1,2}:[0-9]{1,2}$"
            )
            exit(0)
        breaker.setTimestamp(timestamp.string)
        i += 1
    elif args[i] == "-c":
        if len(args) == i + 1:
            print("Missing ciphertext")
            exit(0)
        breaker.setCipherText(args[i + 1])
        i += 1
    elif args[i] == "-f":
        if len(args) == i + 1:
            print("Missing filepath")
            exit(0)
        content = ""
        with open(args[i + 1]) as file:
            content = file.read()
        if content == "":
            print("Something went wrong while reading file")
            exit(0)
        breaker.setTarget(content)
        i += 1
    elif args[i] == "-b":
        breaker.setMode("force")
    elif args[i] == "-h":
        print(
            "\t-e\tSet encrypt mode\n"
            + "\t-t\tSet utc timestamp (HH:mm)\n"
            + "\t-c\tEnter ciphertext\n"
            + "\t-f\tRead plaintext/ciphertext from file\n"
            + "\t-b\tBrute force key\n"
            + "\t-h\tShows this help\n"
        )
        exit(0)
    i += 1

print(breaker.run())


x = cipherbreaker()
x.setMode("encrypt")
x.setTarget('{"user":""}')
x.encrypt()


# pubkey = "-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtn1V6o52TqKaNGd11Opd\n02522R24QS/t8NYRMD3BB7f8O5pCZSfh7/zMM6PTPK8KvZcVndN0B0MqOHCAkSla\nUWO2JlJD0rLs7mFHL9f+sI3pl8QBpS/g/UmmzhCUz1Q3G+3HZLjIF7gaa7QlAx7I\nagKhwAbFH0n/HlJIZMcl6o0kk1KxDGvdoyhTM3yYaMFiiDRhpRMMmfAXObAAFAk5\nOiC6IZ7dFNADDUmy2CFle7HN1WsGMUYzf248N99IQDrwWN4MX2GXXQOwAiaCRrDp\nT/sV8X2oJhug5LnBQEGKdxUkIzG/m9/6xn27LDrNjQWvEimZEfl6c3LgHuBrwRt+\nlQIDAQAB\n-----END RSA PUBLIC KEY-----\n"
# cipherText = "ede02a6c2143c0609c8db332c2ba280639afe95c24b30790df4fee589cd87a687cad448ef33cad050fe88e588af6329ff4cb17ce9157418b13d55a5b8652c3cd0c229723f618709d9781965470aa9fa88a8c41f6cbe9d5ce71362a25a5216bef3e2c4b2963b2f4bd684f988a0e2557bcb6b97e89076b8c375e9068d8c3956e8a6c103b5d57409c9e8c74e35b804207e97ab97dec39a4a0b4a32b4978fb9c2e26cc3d17a0c72110faa4b3e0588019d99fbae6a341e3b44b3eb28bae3d3dddedb258dd68fff148b097fa3164a3de170d7a36ca41b31fa2bb309433344dfe492c1c4c50ce6a1d3e8fb5488e5b52f6f4657236471c98b629c5f22fe2ba80fa0cb6c4d7fdea3d9227ce381bfc2612ba8d24debad3d84d9dce15abac0437adec126f49156c4c0baed671be598ec63596ee8b35cec7746d7b11f24c36ec6aa7e9ba376bc6e83e3ed7c64662f9f9a12054c0453933d8e8e314be32512ab9594939dd6dc8075a56a4761e24247f604590e7969211d5f327a7e8f36c669f192da63494178eb105fe8e963fe684ab5923bdc7b99cffb0b924b07b33ec1011bd8c9076412d5c2ee3cb8e1c41dd531a97bb8145f89d"
# md5Key = "a662a48b31d2dddf93bb2bee967400c1"

# date = datetime.datetime.today()
# hours = date.hour - 1
# n = 10 * math.floor(date.minute / 10)

# hour = 17
# n = 0

# manKey = pubkey[:hours] + str(hours) + pubkey[hours:]
# manKey = (manKey[:n] + str(n) + manKey[n:]).encode()

# md5 = hashlib.md5(manKey).hexdigest()
# aes_key = md5.encode()

# iv = bytes.fromhex(cipherText[:24])
# tag = bytes.fromhex(cipherText[-32:])
# cipherText = bytes.fromhex(cipherText[24:-32])

# cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
# plaintext = cipher.decrypt(cipherText)

# try:
#     cipher.verify(tag)
#     print("The message is authentic:", plaintext.decode())
# except ValueError:
#     print("Key incorrect or message corrupted")
