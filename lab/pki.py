"""A throwaway PKI for the test range: root CA, intermediate CA and leaf certificates.

Nothing here is trusted outside the lab; the root is passed to Sitewarden with --ca-file.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import subprocess
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = dt.UTC


def _name(cn: str, org: str = "Sitewarden Lab") -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


@dataclass
class CA:
    key: object
    cert: x509.Certificate

    @property
    def pem(self) -> bytes:
        return _pem(self.cert)


def make_root(cn: str = "Sitewarden Lab Root CA") -> CA:
    key = ec.generate_private_key(ec.SECP384R1())
    now = dt.datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA384()))
    return CA(key, cert)


def make_intermediate(root: CA, cn: str = "Sitewarden Lab Issuing CA", aia_url: str | None = None) -> CA:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(root.cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
         .not_valid_after(now + dt.timedelta(days=1825))
         .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
         .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root.key.public_key()), critical=False))
    return CA(key, b.sign(root.key, hashes.SHA384()))


def make_leaf(issuer: CA, names: list[str], *, days: int = 90, start_offset_days: int = -1, key_type: str = "ec",
              rsa_bits: int = 2048, aia_url: str | None = None, self_signed: bool = False):
    if key_type == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(UTC)
    subject = _name(names[0], "Sitewarden Lab Site")
    issuer_name = subject if self_signed else issuer.cert.subject
    sign_key = key if self_signed else issuer.key
    nb = now + dt.timedelta(days=start_offset_days)
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(nb + dt.timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(True, False, key_type == "rsa", False, False, False, False, False, False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"), None)]), critical=False)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if not self_signed:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.key.public_key()), critical=False)
    if aia_url:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia_url))]), critical=False)
    cert = b.sign(sign_key, hashes.SHA256())
    return key, cert


def write_pair(directory: pathlib.Path, name: str, key, chain: list[x509.Certificate]) -> tuple[pathlib.Path, pathlib.Path]:
    directory.mkdir(parents=True, exist_ok=True)
    kp = directory / f"{name}.key"
    cp = directory / f"{name}.crt"
    kp.write_bytes(_key_pem(key))
    cp.write_bytes(b"".join(_pem(c) for c in chain))
    return cp, kp


def openssl_sha1_selfsigned(directory: pathlib.Path, name: str, cn: str) -> tuple[pathlib.Path, pathlib.Path]:
    """cryptography refuses to sign with SHA-1, so the legacy certificate comes from the openssl CLI."""
    directory.mkdir(parents=True, exist_ok=True)
    kp, cp = directory / f"{name}.key", directory / f"{name}.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:1024", "-nodes", "-sha1", "-days", "30",
                    "-keyout", str(kp), "-out", str(cp), "-subj", f"/CN={cn}", "-addext", f"subjectAltName=DNS:{cn}"],
                   check=True, capture_output=True)
    return cp, kp


def build_range_pki(directory: pathlib.Path, domain: str = "lab.test", aia_url: str | None = None) -> dict[str, tuple[pathlib.Path, pathlib.Path]]:
    """Every certificate the docker test range needs."""
    root = make_root()
    inter = make_intermediate(root)
    (directory).mkdir(parents=True, exist_ok=True)
    (directory / "root.pem").write_bytes(root.pem)
    (directory / "intermediate.pem").write_bytes(inter.pem)
    (directory / "intermediate.der").write_bytes(inter.cert.public_bytes(serialization.Encoding.DER))
    out = {}
    k, c = make_leaf(inter, [f"modern.{domain}"])
    out["modern"] = write_pair(directory, "modern", k, [c, inter.cert])
    k, c = make_leaf(inter, [f"modern.{domain}"], key_type="rsa")
    out["modern_rsa"] = write_pair(directory, "modern_rsa", k, [c, inter.cert])
    k, c = make_leaf(inter, [f"legacy.{domain}"], key_type="rsa", rsa_bits=2048)
    out["legacy"] = write_pair(directory, "legacy", k, [c, inter.cert])
    k, c = make_leaf(inter, [f"expired.{domain}"], days=30, start_offset_days=-60, key_type="rsa")
    out["expired"] = write_pair(directory, "expired", k, [c, inter.cert])
    k, c = make_leaf(inter, [f"other.{domain}"], key_type="rsa")
    out["wronghost"] = write_pair(directory, "wronghost", k, [c, inter.cert])
    k, c = make_leaf(inter, [f"selfsigned.{domain}"], self_signed=True, key_type="rsa")
    out["selfsigned"] = write_pair(directory, "selfsigned", k, [c])
    k, c = make_leaf(inter, [f"incomplete.{domain}"], key_type="rsa", aia_url=aia_url)
    out["incomplete"] = write_pair(directory, "incomplete", k, [c])  # leaf only, no intermediate
    out["sha1"] = openssl_sha1_selfsigned(directory, "sha1", f"sha1.{domain}")
    return out
