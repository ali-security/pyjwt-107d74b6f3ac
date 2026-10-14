import hashlib
import hmac
import json

import pytest

import jwt
from jwt.algorithms import get_default_algorithms
from jwt.exceptions import InvalidKeyError
from jwt.utils import base64url_encode

from .utils import crypto_required, key_path

priv_key_bytes = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIbBhdo2ah7X32i50GOzrCr4acZTe6BezUdRIixjTAdL
-----END PRIVATE KEY-----"""

pub_key_bytes = (
    b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPL1I9oiq+B8crkmuV4YViiUnhdLjCp3hvy1bNGuGfNL"
)

ssh_priv_key_bytes = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOWc7RbaNswMtNtc+n6WZDlUblMr2FBPo79fcGXsJlGQoAoGCCqGSM49
AwEHoUQDQgAElcy2RSSSgn2RA/xCGko79N+7FwoLZr3Z0ij/ENjow2XpUDwwKEKk
Ak3TDXC9U8nipMlGcY7sDpXp2XyhHEM+Rw==
-----END EC PRIVATE KEY-----"""

ssh_key_bytes = b"""ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJXMtkUkkoJ9kQP8QhpKO/TfuxcKC2a92dIo/xDY6MNl6VA8MChCpAJN0w1wvVPJ4qTJRnGO7A6V6dl8oRxDPkc="""


class TestAdvisory:
    @crypto_required
    def test_ghsa_ffqj_6fqr_9h24(self):
        # Generate ed25519 private key
        # private_key = ed25519.Ed25519PrivateKey.generate()

        # Get private key bytes as they would be stored in a file
        # priv_key_bytes = private_key.private_bytes(
        #     encoding=serialization.Encoding.PEM,
        #     format=serialization.PrivateFormat.PKCS8,
        #     encryption_algorithm=serialization.NoEncryption(),
        # )

        # Get public key bytes as they would be stored in a file
        # pub_key_bytes = private_key.public_key().public_bytes(
        #     encoding=serialization.Encoding.OpenSSH,
        #     format=serialization.PublicFormat.OpenSSH,
        # )

        # Making a good jwt token that should work by signing it
        # with the private key
        # encoded_good = jwt.encode({"test": 1234}, priv_key_bytes, algorithm="EdDSA")
        encoded_good = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoxMjM0fQ.M5y1EEavZkHSlj9i8yi9nXKKyPBSAUhDRTOYZi3zZY11tZItDaR3qwAye8pc74_lZY3Ogt9KPNFbVOSGnUBHDg"

        # Using HMAC with the public key to trick the receiver to think that the
        # public key is a HMAC secret
        encoded_bad = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoxMjM0fQ.6ulDpqSlbHmQ8bZXhZRLFko9SwcHrghCwh8d-exJEE4"

        algorithm_names = list(get_default_algorithms())

        # Both of the jwt tokens are validated as valid
        jwt.decode(
            encoded_good,
            pub_key_bytes,
            algorithms=algorithm_names,
        )

        with pytest.raises(InvalidKeyError):
            jwt.decode(
                encoded_bad,
                pub_key_bytes,
                algorithms=algorithm_names,
            )

        # Of course the receiver should specify ed25519 algorithm to be used if
        # they specify ed25519 public key. However, if other algorithms are used,
        # the POC does not work
        # HMAC specifies illegal strings for the HMAC secret in jwt/algorithms.py
        #
        #        invalid_str ings = [
        #            b"-----BEGIN PUBLIC KEY-----",
        #            b"-----BEGIN CERTIFICATE-----",
        #            b"-----BEGIN RSA PUBLIC KEY-----",
        #            b"ssh-rsa",
        #        ]
        #
        # However, OKPAlgorithm (ed25519) accepts the following in  jwt/algorithms.py:
        #
        #                if "-----BEGIN PUBLIC" in str_key:
        #                    return load_pem_public_key(key)
        #                if "-----BEGIN PRIVATE" in str_key:
        #                    return load_pem_private_key(key, password=None)
        #                if str_key[0:4] == "ssh-":
        #                    return load_ssh_public_key(key)
        #
        # These should most likely made to match each other to prevent this behavior

        # POC for the ecdsa-sha2-nistp256 format.
        # openssl ecparam -genkey -name prime256v1 -noout -out ec256-key-priv.pem
        # openssl ec -in ec256-key-priv.pem -pubout > ec256-key-pub.pem
        # ssh-keygen -y -f ec256-key-priv.pem > ec256-key-ssh.pub

        # Making a good jwt token that should work by signing it with the private key
        # encoded_good = jwt.encode({"test": 1234}, ssh_priv_key_bytes, algorithm="ES256")
        encoded_good = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.NX42mS8cNqYoL3FOW9ZcKw8Nfq2mb6GqJVADeMA1-kyHAclilYo_edhdM_5eav9tBRQTlL0XMeu_WFE_mz3OXg"

        # Using HMAC with the ssh public key to trick the receiver to think that the public key is a HMAC secret
        # encoded_bad = jwt.encode({"test": 1234}, ssh_key_bytes, algorithm="HS256")
        encoded_bad = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoxMjM0fQ.5eYfbrbeGYmWfypQ6rMWXNZ8bdHcqKng5GPr9MJZITU"

        algorithm_names = list(get_default_algorithms())
        # Both of the jwt tokens are validated as valid
        jwt.decode(
            encoded_good,
            ssh_key_bytes,
            algorithms=algorithm_names,
        )

        with pytest.raises(InvalidKeyError):
            jwt.decode(
                encoded_bad,
                ssh_key_bytes,
                algorithms=algorithm_names,
            )

    @staticmethod
    def _forge_hs256(secret):
        header_b64 = base64url_encode(
            json.dumps({"typ": "JWT", "alg": "HS256"}, separators=(",", ":")).encode()
        )
        payload_b64 = base64url_encode(json.dumps({"sub": "attacker"}).encode())
        signing_input = b".".join([header_b64, payload_b64])
        signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
        return b".".join([signing_input, base64url_encode(signature)]).decode()

    @pytest.mark.parametrize(
        "jwk_file",
        ["jwk_rsa_pub.json", "jwk_ec_pub_P-256.json", "jwk_okp_pub_Ed25519.json"],
    )
    def test_hmac_rejects_public_jwk_json_as_secret(self, jwk_file):
        # Algorithm confusion: when the raw JSON of a public JWK reaches
        # decode() as the key, an attacker who knows that public JWK can set
        # alg=HS256 and sign with its bytes as the HMAC secret. The forged
        # token must not verify.
        with open(key_path(jwk_file), "rb") as keyfile:
            jwk_bytes = keyfile.read()

        forged = self._forge_hs256(jwk_bytes)
        algorithm_names = list(get_default_algorithms())

        with pytest.raises(InvalidKeyError, match="looks like a JWK"):
            jwt.decode(forged, jwk_bytes, algorithms=algorithm_names)

        with pytest.raises(InvalidKeyError, match="looks like a JWK"):
            jwt.decode(forged, jwk_bytes.decode("utf-8"), algorithms=["HS256"])

    def test_hmac_rejects_empty_secret(self):
        # An empty HMAC secret lets anybody mint tokens that verify. Tokens
        # forged with an empty key must be rejected, including when the
        # caller relies on the default (empty) key argument.
        forged = self._forge_hs256(b"")

        for empty_key in ("", b""):
            with pytest.raises(InvalidKeyError, match="must not be empty"):
                jwt.decode(forged, empty_key, algorithms=["HS256"])

        with pytest.raises(InvalidKeyError, match="must not be empty"):
            jwt.decode(forged, algorithms=["HS256"])

        with pytest.raises(InvalidKeyError, match="must not be empty"):
            jwt.encode({"sub": "attacker"}, "", algorithm="HS256")
