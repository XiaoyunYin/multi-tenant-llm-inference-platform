"""Platform-specific Docker archives used by the DEC-077 kind rehearsal."""

import hashlib
import json
import re
import tarfile
import tempfile
import uuid
from pathlib import Path

# Existing local rehearsal tools, pinned by image ID: Python 3.12.7 plus the
# tokenizer/Jinja dependencies that the real FakeBackend requires. $0 only.
LINUX_E2E_IMAGE = "sha256:1726ddf276483b717dd81d148bca9bd21f60a11d393bf2680c7812006dc9e7f4"

KIND_LOCAL_IMAGE_TAGS = {
    "redis": "dec077-kind/redis:amd64",
    "nginx": "dec077-kind/nginx:amd64",
    "prometheus": "dec077-kind/prometheus:amd64",
    "python": "dec077-kind/python:amd64",
}

KIND_CONTROLLER_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}
ARCHIVE_BUILD_TIMEOUT_S = 300
ARCHIVE_EXPORT_TIMEOUT_S = 180
ARCHIVE_PREFETCH_CLEANUP_TIMEOUT_S = 60
KIND_ARCHIVE_LOAD_TIMEOUT_S = 180
KIND_LOCAL_IMAGE_INSPECT_TIMEOUT_S = 90
KIND_LOCAL_IMAGE_LOAD_TIMEOUT_S = 180


def crictl_image_resolution_matches(reference, exit_code, status, *, expected_config_digest=None):
    """Require a CRI tag match, and pin config IDs for archived upstream images."""
    if exit_code != 0 or not isinstance(status, dict):
        return False
    image_id = status.get("id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        return False
    if "/" not in reference:
        expected_repo_tag = "docker.io/library/" + reference
    else:
        first = reference.split("/", 1)[0]
        expected_repo_tag = reference if "." in first or ":" in first else "docker.io/" + reference
    repo_tags = status.get("repoTags")
    if not isinstance(repo_tags, list) or expected_repo_tag not in repo_tags:
        return False
    return expected_config_digest is None or image_id == expected_config_digest


def rewrite_kind_workload_images(
    manifest: dict, *, replacements: dict, allowed_images: set
) -> list[str]:
    """Pin every controller template to an image already loaded into kind."""
    used = set()
    for resource in manifest.get("items", []):
        if resource.get("kind") not in KIND_CONTROLLER_KINDS:
            continue
        pod = resource.get("spec", {}).get("template", {}).get("spec")
        if not isinstance(pod, dict):
            raise ValueError("kind_controller_pod_template_missing")
        containers = [*pod.get("initContainers", []), *pod.get("containers", [])]
        if not containers:
            raise ValueError("kind_controller_containers_missing")
        for container in containers:
            source = container.get("image")
            image = replacements.get(source, source)
            if not isinstance(image, str) or image not in allowed_images:
                raise ValueError("kind_controller_image_not_loaded:" + str(source))
            container["image"] = image
            container["imagePullPolicy"] = "Never"
            used.add(image)
    return sorted(used)


def inspect_docker_archive(path: Path, *, expected_local_tag: str | None = None) -> dict:
    path = Path(path)
    with tarfile.open(path, "r:*") as archive:
        members = {item.name for item in archive.getmembers() if item.isfile()}
        manifest_file = archive.extractfile("manifest.json")
        if manifest_file is None:
            raise ValueError("docker_archive_manifest_missing")
        manifest = json.loads(manifest_file.read())
        if not isinstance(manifest, list) or not manifest:
            raise ValueError("docker_archive_manifest_empty")
        references = []
        platforms = set()
        repo_tags = set()
        config_digests = set()
        for entry in manifest:
            if not isinstance(entry, dict) or not isinstance(entry.get("Config"), str):
                raise ValueError("docker_archive_config_descriptor_missing")
            if entry["Config"] not in members:
                raise ValueError("docker_archive_descriptor_missing:" + entry["Config"])
            layers = entry.get("Layers")
            if not isinstance(layers, list) or any(not isinstance(layer, str) for layer in layers):
                raise ValueError("docker_archive_layer_descriptors_invalid")
            tags = entry.get("RepoTags") or []
            if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
                raise ValueError("docker_archive_repo_tags_invalid")
            repo_tags.update(tags)
            config_file = archive.extractfile(entry["Config"])
            if config_file is None:
                raise ValueError("docker_archive_config_descriptor_missing")
            try:
                config_bytes = config_file.read()
                config = json.loads(config_bytes)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("docker_archive_config_invalid") from exc
            if (
                not isinstance(config, dict)
                or not config.get("os")
                or not config.get("architecture")
            ):
                raise ValueError("docker_archive_config_platform_missing")
            platforms.add(f"{config['os']}/{config['architecture']}")
            config_digests.add("sha256:" + hashlib.sha256(config_bytes).hexdigest())
            references.extend((entry["Config"], *layers))
        if platforms != {"linux/amd64"}:
            raise ValueError("docker_archive_platform_mismatch:" + ",".join(sorted(platforms)))
        missing = sorted(set(references) - members)
    if missing:
        raise ValueError("docker_archive_descriptor_missing:" + ",".join(missing))
    if expected_local_tag is not None and repo_tags != {expected_local_tag}:
        raise ValueError("docker_archive_local_tag_mismatch")
    if len(config_digests) != 1:
        raise ValueError("docker_archive_config_digest_ambiguous")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return {
        "complete": True,
        "manifest_entries": len(manifest),
        "platform": "linux/amd64",
        "repo_tags": sorted(repo_tags),
        "config_digest": next(iter(config_digests)),
        "descriptor_count": len(references),
        "referenced_files": sorted(set(references)),
        "missing_files": [],
        "bytes": path.stat().st_size,
        "sha256": digest.hexdigest(),
    }


def save_amd64_archive(
    image: str,
    path: Path,
    run,
    *,
    local_tag: str | None = None,
    timeout=ARCHIVE_EXPORT_TIMEOUT_S,
) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    prefetch_ref = local_tag or f"dec077-archive-prefetch:{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory(prefix="dec077-archive-prefetch-", dir=path.parent) as temp:
        context = Path(temp)
        dockerfile = context / "Dockerfile"
        dockerfile.write_text(f"FROM {image}\n", encoding="ascii")
        command_records = []

        def record_run(argv, *, timeout):
            result = run(argv, timeout=timeout)
            if isinstance(result, dict):
                command_records.append(result)
            return result

        # Docker 29's containerd store can list an amd64 child while lacking
        # exportable blobs. A pinned-base BuildKit load materializes those blobs.
        prefetch = record_run(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                "linux/amd64",
                "--tag",
                prefetch_ref,
                "--load",
                "--file",
                dockerfile,
                context,
            ],
            timeout=max(timeout, ARCHIVE_BUILD_TIMEOUT_S),
        )
        try:
            record_run(
                [
                    "docker",
                    "image",
                    "save",
                    "--platform",
                    "linux/amd64",
                    "--output",
                    path,
                    local_tag or image,
                ],
                timeout=timeout,
            )
            result = inspect_docker_archive(path, expected_local_tag=local_tag)
        finally:
            record_run(
                ["docker", "image", "rm", prefetch_ref],
                timeout=ARCHIVE_PREFETCH_CLEANUP_TIMEOUT_S,
            )
    return {
        "image": image,
        "pinned_reference": image,
        "local_tag": local_tag,
        "config_digest": result["config_digest"],
        "export_prefetch": "buildx_from_pinned_base",
        "commands": command_records,
        **(prefetch if isinstance(prefetch, dict) else {}),
        **result,
    }
