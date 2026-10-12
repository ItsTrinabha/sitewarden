import pathlib
import shutil
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))  # so `lab` imports

from lab import dnsserver, world  # noqa: E402
from sitewarden.net import Network  # noqa: E402


def pytest_collection_modifyitems(config, items):
    has_docker = shutil.which("docker") is not None
    for item in items:
        if "docker" in item.keywords and not has_docker:
            item.add_marker(pytest.mark.skip(reason="docker not available"))


@pytest.fixture(scope="session")
def lab_dns():
    resolver, anchors = world.build()
    port, stop = dnsserver.serve(resolver)
    yield port, anchors
    stop()


@pytest.fixture
def lab_net(lab_dns):
    port, _ = lab_dns
    return Network(allow_private=True, nameservers=["127.0.0.1"], dns_port=port, dns_timeout=2)


@pytest.fixture(scope="session")
def openssl():
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available")
    return "openssl"
