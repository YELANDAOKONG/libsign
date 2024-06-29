# -*- encoding: utf-8 -*-
import os
import sys
import time
import base64
import random
import string
import secrets
import hashlib


def get_sha256(bytes_data) -> str:
    """Helper function to mimic GetSha256 behavior."""
    return hashlib.sha256(bytes_data).hexdigest()


def get_sha384(bytes_data) -> str:
    """Helper function to mimic GetSha384 behavior."""
    return hashlib.sha384(bytes_data).hexdigest()


def get_sha512(bytes_data) -> str:
    """Helper function to mimic GetSha512 behavior."""
    return hashlib.sha512(bytes_data).hexdigest()


def random_string(length: int) -> str:
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


