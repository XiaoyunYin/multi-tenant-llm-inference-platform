"""Public AWS release facts and one-time first-contact binding.

The session nvidia-smi hash detects changes; it does not authenticate the binary.
The managed node release, published branch and node UID are reviewed inputs.
"""

import datetime as dt
import hashlib
import json
import re
import urllib.request
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath


def need(value, reason):
    if not value:
        raise ValueError("device:" + reason)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def coordinates(release):
    match = re.fullmatch(r"(\d+\.\d+)\.\d+-(\d{8})", release)
    need(match is not None, "driver_release_mismatch")
    tag = "v" + match[2]
    return match[1], tag, "https://github.com/awslabs/amazon-eks-ami/releases/tag/" + tag


class Tables(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self.table, self.row, self.cell = [], None, None, None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.table = []
        elif tag == "tr":
            self.row = []
        elif tag in ("th", "td"):
            self.cell = []
            self.span = int(dict(attrs).get("colspan", "1"))
            need(1 <= self.span <= 10, "unresolved:node_driver_binding")

    def handle_data(self, value):
        if self.cell is not None:
            self.cell.append(value)

    def handle_endtag(self, tag):
        if tag in ("th", "td") and self.cell is not None:
            self.row.extend(["".join(self.cell).strip()] * self.span)
            self.cell = None
        elif tag == "tr" and self.row is not None:
            self.table.append(self.row)
            self.row = None
        elif tag == "table":
            self.tables.append(self.table)
            self.table = None


def published_driver(raw, *, image_release, utc, package="nvidia-kmod (default)"):
    """Parse only the named release's x86 NVIDIA column; never choose by observation."""
    minor, tag, url = coordinates(image_release)
    need(
        package in ("nvidia-kmod (default)", "nvidia-kmod (latest)", "nvidia-driver-latest-dkms"),
        "unresolved:node_driver_binding",
    )
    doc = json.loads(raw)
    need(doc.get("tag_name") == tag and doc.get("html_url") == url, "driver_release_mismatch")
    sections = re.findall(
        r"<details>\s*<summary><b>Kubernetes "
        + re.escape(minor)
        + r"</b></summary>(.*?)</details>",
        doc.get("body", ""),
        re.S,
    )
    need(len(sections) == 1, "unresolved:node_driver_binding")
    parser = Tables()
    parser.feed(sections[0])
    name = "amazon-eks-node-al2023-x86_64-nvidia-" + minor + "-" + tag
    need(
        any(row[:2] == [name, image_release] for table in parser.tables for row in table),
        "driver_release_mismatch",
    )
    values = []
    for table in parser.tables:
        if not table or not table[0] or table[0][0] != "Package":
            continue
        header = table[0]
        need(header.count("AL2023_x86_64_NVIDIA") == 1, "unresolved:node_driver_binding")
        index = header.index("AL2023_x86_64_NVIDIA")
        values.extend(
            row[index] for row in table[1:] if len(row) == len(header) and row[0] == package
        )
    need(
        len(values) == 1 and re.fullmatch(r"\d+\.\d+(?:\.\d+)?", values[0]),
        "unresolved:node_driver_binding",
    )
    stamp = dt.datetime.fromisoformat(utc)
    need(stamp.utcoffset() == dt.timedelta(0), "driver_publication_utc")
    return {
        "schema": "inf037b-published-driver-v1",
        "image_release": image_release,
        "variant": "AL2023_x86_64_NVIDIA",
        "package": package,
        "driver_version": values[0],
        "url": url,
        "response_url": "https://api.github.com/repos/awslabs/amazon-eks-ami/releases/tags/" + tag,
        "utc": utc,
        "response_sha256": hashlib.sha256(raw).hexdigest(),
    }


def refresh_driver(image_release, *, package="nvidia-kmod (default)", fetch=None):
    """Read-only public HTTPS, independent of AWS credentials; no call in tests."""
    _, tag, _ = coordinates(image_release)
    url = "https://api.github.com/repos/awslabs/amazon-eks-ami/releases/tags/" + tag
    if fetch is None:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "inf037b-readonly-driver-refresh",
            },
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            need(response.url == url, "driver_publication_url")
            raw = response.read(1_048_577)
    else:
        raw = fetch(url)
    need(len(raw) <= 1_048_576, "driver_publication_size")
    value = published_driver(
        raw, image_release=image_release, package=package, utc=dt.datetime.now(dt.UTC).isoformat()
    )
    return value, raw


def release_evidence(first, published, *, node_uid, image_release):
    """Bind once before P. A file hash is session change detection, not authentication."""
    need(
        type(published) is dict
        and published.get("schema") == "inf037b-published-driver-v1"
        and published.get("driver_version"),
        "unresolved:node_driver_binding",
    )
    _, _, url = coordinates(image_release)
    need(
        published["image_release"] == image_release == first["image_release"],
        "driver_release_mismatch",
    )
    need(
        published["url"] == url and published["variant"] == "AL2023_x86_64_NVIDIA",
        "driver_publication_binding",
    )
    need(first["schema"] == "inf037b-driver-first-contact-v1", "driver_first_contact_schema")
    need(first["node_uid"] == node_uid and bool(node_uid), "driver_node_uid_mismatch")
    need(first["driver_version"] == published["driver_version"], "driver_version_mismatch")
    from .inf037b_device import smi_xml

    xml = first["raw_xml"].encode()
    need(hashlib.sha256(xml).hexdigest() == first["raw_sha256"], "driver_first_contact_raw")
    smi_xml(xml, first["driver_version"])
    stamp = dt.datetime.fromisoformat(published["utc"])
    need(stamp.utcoffset() == dt.timedelta(0), "driver_publication_utc")
    need(
        re.fullmatch(r"[0-9a-f]{64}", first["nvidia_smi_sha256"])
        and (
            PurePosixPath(first["nvidia_smi_path"]).is_absolute()
            or Path(first["nvidia_smi_path"]).is_absolute()
        ),
        "driver_first_contact_identity",
    )
    need(re.fullmatch(r"[0-9a-f]{64}", published["response_sha256"]), "driver_publication_binding")
    return {
        "schema": "inf037b-driver-release-evidence-v1",
        "node_uid": node_uid,
        "image_release": image_release,
        "driver_version": first["driver_version"],
        "nvidia_smi_path": first["nvidia_smi_path"],
        "nvidia_smi_sha256": first["nvidia_smi_sha256"],
        "first_contact": first,
        "published": published,
        "first_contact_sha256": hashlib.sha256(canonical(first)).hexdigest(),
        "published_sha256": hashlib.sha256(canonical(published)).hexdigest(),
        "hash_authority": "session_change_detection_only_not_binary_authentication",
    }
