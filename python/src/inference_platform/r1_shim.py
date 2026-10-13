"""Small explicit docker/chronyc fixture shim; never runs either command."""

import json
import os
import sys
import time
from pathlib import Path


def main():
    state = json.loads(Path(os.environ["R1_SHIM_STATE"]).read_bytes())
    args = sys.argv[1:]
    with Path(state["calls"]).open("a") as log:
        log.write(
            json.dumps(
                {
                    "program": Path(sys.argv[0]).name,
                    "args": args,
                    "monotonic_s": time.perf_counter(),
                }
            )
            + "\n"
        )
    if Path(sys.argv[0]).name == "chronyc":
        print("Leap status : Normal\nReference ID : LOOPBACK-FIXTURE")
    elif args[:2] == ["image", "inspect"]:
        print(json.dumps([{"Id": "sha256:fixture-image", "Config": {"Env": []}}]))
    elif args[0] == "inspect":
        print(
            json.dumps(
                [
                    {
                        "Id": args[1],
                        "Image": "sha256:fixture-image",
                        "State": {"Running": True, "StartedAt": "2026-10-06T00:00:00Z"},
                        "Config": {
                            "Image": state["image"],
                            "Cmd": state["command"],
                            "Env": ["VLLM_SERVER_DEV_MODE=1"],
                        },
                    }
                ]
            )
        )
    else:
        raise ValueError("unsupported fixture shim command")
