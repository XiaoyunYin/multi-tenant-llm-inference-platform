"""Install the pinned S3 SDK in the ephemeral Linux runner, then run its argv."""

import os
import shutil
import subprocess
import sys


def main():
    if not shutil.which("git"):
        subprocess.run(["apt-get", "update"], check=True)
        subprocess.run(["apt-get", "install", "-y", "git"], check=True)
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--quiet",
            "--no-cache-dir",
            "--target",
            "/tmp/third-party",
            "--root-user-action=ignore",
            "boto3==1.43.123",
        ],
        check=True,
    )
    environment = dict(os.environ)
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PYTHONPATH"] = "/tmp/third-party:/repo/python/src:/repo/python/tests"
    os.execvpe(sys.executable, [sys.executable, *sys.argv[1:]], environment)


if __name__ == "__main__":
    main()
