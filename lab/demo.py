"""Run the web app against the Docker test range so the UI can be tried without internet access.

    python -m lab.demo            # http://127.0.0.1:8000, then scan modern.lab.test or legacy.lab.test
"""

from __future__ import annotations

import os
import sys
import tempfile

from sitewarden.net import Network
from sitewarden.scan import ScanOptions

from . import dnsserver, world
from . import range as lab_range


def main() -> int:
    import uvicorn

    from sitewarden.web.app import create_app

    lab_range.up()
    resolver, anchors = world.build(domain=lab_range.DOMAIN)
    dns_port, stop = dnsserver.serve(resolver)
    ports = {host: (https, http) for _l, host, https, http in lab_range.TARGETS}
    root = (lab_range.GEN / "certs" / "root.pem").read_bytes()

    def net():
        return Network(allow_private=True, nameservers=["127.0.0.1"], dns_port=dns_port, extra_roots=[root],
                       dns_timeout=2)

    def options(target: str) -> ScanOptions:
        https, http = ports.get(target, (443, 80))
        return ScanOptions(port=https, http_port=http, smtp=False, dnssec_anchors=anchors, timeout=4)

    db = os.path.join(tempfile.mkdtemp(), "demo.db")
    app = create_app(db, net_factory=net, scan_options=options)
    print("Lab targets: " + ", ".join(ports))
    try:
        uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("PORT", "8000")), log_level="warning")
    finally:
        stop()
        lab_range.down()
    return 0


if __name__ == "__main__":
    sys.exit(main())
