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


def sign_authorization_password(password: str, timestamp: int):
    real_timestamp = timestamp // (1000 * 30)
    result = get_sha384((str(real_timestamp) + password + str(real_timestamp)).encode('utf-8'))
    result = get_sha512((str(real_timestamp) + result + str(real_timestamp)).encode('utf-8'))
    return result


def sign_authorization_token(token: str, timestamp: int):
    real_timestamp = timestamp // (1000 * 30)
    result = get_sha256((str(real_timestamp) + token + str(real_timestamp)).encode('utf-8'))
    result = get_sha384((str(real_timestamp) + result + str(real_timestamp)).encode('utf-8'))
    result = get_sha512((str(real_timestamp) + result + str(real_timestamp)).encode('utf-8'))
    return result


def sign_authorization_secret(access_key: str, secret_ket: str, timestamp: int):
    real_timestamp = timestamp // (1000 * 30)
    result = get_sha256((str(real_timestamp) + access_key + result + secret_ket + str(real_timestamp)).encode('utf-8'))
    result = get_sha384((str(real_timestamp) + secret_ket + result + access_key + str(real_timestamp)).encode('utf-8'))
    result = get_sha384((str(real_timestamp) + access_key + result + access_key + str(real_timestamp)).encode('utf-8'))
    result = get_sha384((str(real_timestamp) + secret_ket + result + secret_ket + str(real_timestamp)).encode('utf-8'))
    result = get_sha512((str(real_timestamp) + secret_ket + result + access_key + str(
        real_timestamp) + secret_ket + str(real_timestamp)).encode('utf-8'))
    result = get_sha384((str(real_timestamp) + access_key + result + secret_ket + str(
        real_timestamp) + access_key + str(real_timestamp)).encode('utf-8'))
    result = get_sha512((str(real_timestamp) + access_key + result + secret_ket + str(
        real_timestamp) + secret_ket + str(real_timestamp)).encode('utf-8'))
    result = get_sha512((str(real_timestamp) + secret_ket + result + secret_ket + str(
        real_timestamp) + access_key + str(real_timestamp)).encode('utf-8'))
    result = get_sha512((str(real_timestamp) + secret_ket + result + access_key + str(
        real_timestamp) + secret_ket + str(real_timestamp)).encode('utf-8'))
    result = get_sha512((str(real_timestamp) + access_key + result + secret_ket + str(
        real_timestamp) + secret_ket + access_key + str(real_timestamp) + result).encode('utf-8'))
    return result


def random_string(length: int) -> str:
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))


def random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)
