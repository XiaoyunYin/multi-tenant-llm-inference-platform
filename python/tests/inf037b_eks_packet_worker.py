"""Actual process-cut witness at the production barrier's persisted intent."""

import os
import sys
from pathlib import Path

from inf037b_eks_supervisor_worker import FileJournal

from inference_platform.inf037b_archive import strict_json
from inference_platform.inf037b_eks_packet import CanonicalPacket
from inference_platform.inf037b_eks_stores import RecoveryRepository


def main():
    root = Path(sys.argv[1])
    config = strict_json((root / "cut-config.json").read_bytes())
    journal = FileJournal(root / "cut-journal", {}, initialize=True)
    repository = RecoveryRepository(
        binding=config["stores"],
        journal=journal,
        store_ports={},
        access=None,
        clock=lambda: 1000001,
        metadata_root=root / "unit-recovery/meta",
    )

    def cut(phase):
        if phase == "intent":
            os._exit(73)

    packet = CanonicalPacket(
        repository=repository,
        root=root / "unit-recovery/canonical",
        binding=config["binding"],
        pins=config["pins"],
        clock=lambda: 1000001,
        hook=cut,
    )
    packet.seal({}, {}, 1120000)


if __name__ == "__main__":
    main()
