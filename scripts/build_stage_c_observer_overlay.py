"""Build the source-only draft-r18 overlay from the exact local vLLM pin.

No image pull, cloud call, installation or serving launch. The resulting diff
and manifest are review artifacts, not serving-image or GPU fitness evidence.
"""

import argparse
import ast
import gzip
import hashlib
import io
import json
import subprocess
import tarfile
from pathlib import Path

PIN = "98dff2a81d747d1dba01a47f939f48c3526d4206"
BASE_IMAGE = "sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b"
FILES = (
    "vllm/v1/engine/core.py",
    "vllm/v1/core/sched/scheduler.py",
    "vllm/v1/core/block_pool.py",
    "vllm/distributed/kv_events.py",
)
HELPER = "vllm/v1/engine/stage_c_observer.py"
IMPORT = "from vllm.v1.engine import stage_c_observer as _stage_c\n"


def git(root, *args, data=None):
    return subprocess.run(
        ["git", "-C", str(root), *args], input=data, capture_output=True, check=True
    ).stdout


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError("Pinned source clause differs: " + repr(old))
    return source.replace(old, new)


def constructor(source, cls):
    tree = ast.parse(source)
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == cls
    )
    method = next(
        node
        for node in target.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    )
    lines = source.splitlines(keepends=True)
    lines.insert(
        method.end_lineno,
        f'        _stage_c.register(self, "{cls}.__init__", __file__)\n',
    )
    return "".join(lines)


def patches(pristine):
    result = {}
    core = pristine[FILES[0]]
    core = once(
        core,
        "        enable_envs_cache()\n",
        "        enable_envs_cache()\n        _stage_c.start(self, __file__)\n",
    )
    # Only the popped batch-queue output wait, not step's resolved Future.
    old = "            model_output = future.result()\n"
    new = (
        '            _stage_c_block = _stage_c.call("before_wait", future)\n'
        "            try:\n                model_output = future.result()\n"
        '            finally:\n                _stage_c.call("after_wait", _stage_c_block)\n'
    )
    head, batch_method = core.split("    def step_with_batch_queue", 1)
    core = head + "    def step_with_batch_queue" + once(batch_method, old, new)
    core = once(
        core,
        "                req = self.input_queue.get(block=block)\n",
        '                _stage_c_block = _stage_c.call("before_idle", block)\n'
        "                try:\n                    req = self.input_queue.get(block=block)\n"
        '                finally:\n                    _stage_c.call("after_wait", _stage_c_block)\n',
    )
    core = once(
        core,
        "        self.post_step(model_executed)\n",
        '        self.post_step(model_executed)\n        _stage_c.call("capture_due")\n',
    )
    core = once(
        core,
        "            callback(self)\n",
        '            _stage_c.call("serial", "callbacks")\n            callback(self)\n',
    )
    tree = ast.parse(core)
    target = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "EngineCoreProc"
    )
    handle = next(
        n
        for n in target.body
        if isinstance(n, ast.FunctionDef) and n.name == "_handle_client_request"
    )
    lines = core.splitlines(keepends=True)
    first = (
        handle.body[1]
        if isinstance(handle.body[0], ast.Expr)
        and isinstance(handle.body[0].value, ast.Constant)
        else handle.body[0]
    )
    lines.insert(first.lineno - 1, '        _stage_c.call("serial", "handled")\n')
    core = "".join(lines)
    # Reset observation wraps the native call's existing body, preserving its
    # result/exception and invocation count. It invalidates the old epoch first.
    tree = ast.parse(core)
    cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "EngineCore"
    )
    reset = next(
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "reset_prefix_cache"
    )
    lines = core.splitlines(keepends=True)
    first = (
        reset.body[1]
        if isinstance(reset.body[0], ast.Expr)
        and isinstance(reset.body[0].value, ast.Constant)
        else reset.body[0]
    )
    lines.insert(first.lineno - 1, '        _stage_c.call("observe_reset")\n')
    core = "".join(lines)
    core = once(
        core,
        "        return self.scheduler.reset_prefix_cache(\n"
        "            reset_running_requests, reset_connector\n        )\n",
        "        try:\n"
        "            _stage_c_result = self.scheduler.reset_prefix_cache(\n"
        "                reset_running_requests, reset_connector\n            )\n"
        "        except BaseException:\n"
        '            _stage_c.call("reset_result", None, True)\n            raise\n'
        '        _stage_c.call("reset_result", _stage_c_result, False)\n'
        "        return _stage_c_result\n",
    )
    core = once(
        core,
        '        logger.debug_once("[shutdown] EngineCore: tearing down local resources")\n',
        '        _stage_c.call("close")\n'
        '        logger.debug_once("[shutdown] EngineCore: tearing down local resources")\n',
    )
    result[FILES[0]] = core

    scheduler = constructor(pristine[FILES[1]], "Scheduler")
    scheduler = once(
        scheduler,
        "        return scheduler_output\n",
        '        _stage_c.call("observe_schedule", scheduler_output)\n'
        "        return scheduler_output\n",
    )
    # Owner state is modified on scheduled requests even when refcounts do not
    # change; a trailing output skipped for a finished request is not mutation.
    scheduler = once(
        scheduler,
        "            request.num_computed_tokens += num_scheduled_token\n",
        "            _stage_c.mutation(self)\n"
        "            request.num_computed_tokens += num_scheduled_token\n",
    )
    scheduler = once(
        scheduler,
        "            req_index = model_runner_output.req_id_to_index[req_id]\n",
        "            _stage_c.mutation(self)\n"
        "            req_index = model_runner_output.req_id_to_index[req_id]\n",
    )
    result[FILES[1]] = scheduler

    pool = constructor(pristine[FILES[2]], "BlockPool")
    pool = once(
        pool,
        "            if new_hashes is not None:\n",
        '            _stage_c.call("observe_cache", self, request,\n'
        "                          num_cached_blocks + i, blk, block_hash_with_group_id)\n"
        "            if new_hashes is not None:\n",
    )
    pool = once(
        pool,
        "        return ret\n",
        '        _stage_c.call("observe_allocation", self, ret)\n        return ret\n',
    )
    pool = once(
        pool,
        "        num_used_blocks = self.num_gpu_blocks - self.get_num_free_blocks()\n",
        "        _stage_c.mutation(self)\n"
        "        num_used_blocks = self.num_gpu_blocks - self.get_num_free_blocks()\n",
    )
    # Increment for every actual reference/hash/free-list mutation in this pin.
    # Loops keep generators and native iteration order intact.
    pool = "".join(
        line[: len(line) - len(line.lstrip())] + "_stage_c.mutation(self)\n" + line
        if line.strip() == "block.ref_cnt += 1"
        else line
        for line in pool.splitlines(keepends=True)
    )
    pool = once(
        pool,
        "            block.ref_cnt -= 1\n",
        "            _stage_c.mutation(self)\n            block.ref_cnt -= 1\n",
    )
    # Hash insert/remove covers cache_full_blocks, eviction and alias transitions.
    tree = ast.parse(pool)
    cls = next(
        n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "BlockPool"
    )
    lines = pool.splitlines(keepends=True)
    inserts = []
    for method in cls.body:
        if isinstance(method, ast.FunctionDef) and method.name in (
            "_insert_block_hash",
            "_remove_cached_block_hashes",
        ):
            first = (
                method.body[1]
                if isinstance(method.body[0], ast.Expr)
                and isinstance(method.body[0].value, ast.Constant)
                else method.body[0]
            )
            inserts.append(first.lineno - 1)
    for position in sorted(inserts, reverse=True):
        lines.insert(position, "        _stage_c.mutation(self)\n")
    result[FILES[2]] = "".join(lines)

    publisher = pristine[FILES[3]]
    publisher = once(
        publisher,
        "        self._thread.start()\n",
        '        _stage_c.register(self, "ZmqEventPublisher.__init__", __file__)\n'
        "        self._thread.start()\n",
    )
    publisher = once(
        publisher,
        "        self._event_queue.put(events)\n",
        '        _stage_c.call("observe_enqueue", events)\n'
        "        try:\n            self._event_queue.put(events)\n"
        "        except BaseException:\n"
        '            _stage_c.call("observe_enqueue", events, False, True)\n'
        "            raise\n"
        '        _stage_c.call("observe_enqueue", events, True)\n',
    )
    publisher = once(
        publisher,
        "                seq = next(self._seq_gen)\n",
        "                seq = next(self._seq_gen)\n"
        '                _stage_c.call("observe_sequence", event, seq)\n',
    )
    publisher = once(
        publisher,
        "                self._pub.send_multipart((self._topic_bytes, seq_bytes, payload))\n",
        "                self._pub.send_multipart((self._topic_bytes, seq_bytes, payload))\n"
        '                _stage_c.call("observe_send", event)\n',
    )
    publisher = once(
        publisher,
        "                # Publishing failed;  back-off a bit to avoid a tight error loop\n",
        '                _stage_c.call("observe_send", event, True)\n'
        "                # Publishing failed;  back-off a bit to avoid a tight error loop\n",
    )
    result[FILES[3]] = publisher
    for path, source in result.items():
        # Place after ordinary imports, before module runtime assignments.
        tree = ast.parse(source)
        imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        lines = source.splitlines(keepends=True)
        lines.insert(imports[-1].end_lineno, "\n" + IMPORT)
        result[path] = "".join(lines)
        ast.parse(result[path], filename=path)
    return result


def build(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    if git(source, "rev-parse", "HEAD").decode().strip() != PIN or git(
        source, "status", "--porcelain"
    ):
        raise ValueError("Requires clean exact pinned source")
    output.mkdir(parents=True, exist_ok=False)
    work = output / "tree"
    subprocess.run(
        ["git", "clone", "--shared", "--no-checkout", str(source), str(work)],
        capture_output=True,
        check=True,
    )
    git(work, "-c", "core.autocrlf=false", "checkout", "--detach", PIN)
    pristine = {p: git(source, "show", PIN + ":" + p).decode("utf-8") for p in FILES}
    overlay = patches(pristine)
    helper = (
        Path(__file__).resolve().parents[1]
        / "python/src/inference_platform/stage_c_observer.py"
    )
    overlay[HELPER] = helper.read_text(encoding="utf-8")
    for path, text in overlay.items():
        if "\r" in text:
            raise ValueError("Non-LF source")
        (work / path).write_bytes(text.encode("utf-8"))
    attrs = git(work, "check-attr", "--all", "--", *overlay)
    if b"filter:" in attrs or b"working-tree-encoding:" in attrs:
        raise ValueError("Unreviewed source filter/encoding")
    git(work, "-c", "core.autocrlf=false", "add", "--", *overlay)
    patch = git(
        work,
        "-c",
        "core.quotePath=true",
        "diff",
        "--cached",
        "--binary",
        "--full-index",
        "--no-ext-diff",
        "--no-renames",
        PIN,
        "--",
    )
    if git(work, "diff", "--", *overlay):
        raise ValueError("Staged/worktree mismatch")
    (output / "observational.patch").write_bytes(patch)
    # Verify exact bytes apply to a separate pristine checkout, never to source.
    verify = output / "verify"
    subprocess.run(
        ["git", "clone", "--shared", "--no-checkout", str(source), str(verify)],
        capture_output=True,
        check=True,
    )
    git(verify, "-c", "core.autocrlf=false", "checkout", "--detach", PIN)
    git(verify, "-c", "core.autocrlf=false", "apply", "--check", "-", data=patch)
    git(verify, "-c", "core.autocrlf=false", "apply", "-", data=patch)
    archive_buffer = io.BytesIO()
    with gzip.GzipFile(
        fileobj=archive_buffer, mode="wb", mtime=0, filename=""
    ) as compressed:
        with tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive:
            for path in sorted(overlay):
                data = (work / path).read_bytes()
                if (verify / path).read_bytes() != data:
                    raise ValueError("Applied overlay mismatch")
                entry = tarfile.TarInfo(path)
                entry.size, entry.mode = len(data), 0o444
                archive.addfile(entry, io.BytesIO(data))
    archive = archive_buffer.getvalue()
    (output / "overlay.tar.gz").write_bytes(archive)
    manifest = {
        "base_image": BASE_IMAGE,
        "source_commit": PIN,
        "diff_sha256": hashlib.sha256(patch).hexdigest(),
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
        "archive_bytes": len(archive),
        "unpacked_bytes": sum(len(s.encode()) for s in overlay.values()),
        "git_version": git(source, "--version").decode().strip(),
        "attributes": attrs.decode(),
        "serving_image_verified": False,
        "files": {
            p: {
                "pristine_sha256": None
                if p == HELPER
                else hashlib.sha256(pristine[p].encode()).hexdigest(),
                "overlay_sha256": hashlib.sha256(s.encode()).hexdigest(),
                "size": len(s.encode()),
            }
            for p, s in overlay.items()
        },
    }
    encoded = (
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    (output / "manifest.json").write_bytes(encoded)
    (output / "manifest.sha256").write_text(hashlib.sha256(encoded).hexdigest() + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
