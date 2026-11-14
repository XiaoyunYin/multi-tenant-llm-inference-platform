"""Offline behavioral mutation checks in disposable source copies; requires Redis."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile


def main() -> None:
    if not os.environ.get("REDIS_TEST_ADDR"):
        raise SystemExit("REDIS_TEST_ADDR must name disposable local Redis")
    root = Path(__file__).resolve().parents[1]
    backend = "internal/gateway/backend.go"
    handler = "internal/gateway/handler.go"
    recovery = "TestRedisDiscoveryStartAndRecoveryWithholdUnsampled"
    hung = "TestHealthHungPeerDoesNotStaleHealthyReplica"
    counter = "TestAfterAdmitRevalidationCausesCounted"
    addition = "TestDiscoveryMemberAdditionKeepsServingWithholdsReports"
    ttl = "TestRedisM5RehearsalTTLControls"
    rollout = "TestRedisM5RehearsalReplacementFailureRollback"
    discovery = "internal/gateway/discovery.go"
    lua = "internal/admission/scripts/admit.lua"
    withheld = "TestRedisCoordinatorWithheldMarkerBlocksRestoration"
    mutations = [
        (
            "withheld_marker_dropped",
            "internal/admission/coordinator.go",
            [('op = "unknown"', "return nil")],
            withheld,
            "fresh withheld marker must block restoration: B=6 code=allowed err=<nil>; want B=3 allowed",
        ),
        (
            "unsampled_known_count",
            backend,
            [
                (
                    "known := !r.discoveryUnknown.Load() && r.allSampledLocked()",
                    "known := !r.discoveryUnknown.Load()",
                )
            ],
            recovery,
            "published synthetic known zero before health samples",
        ),
        (
            "unsampled_local_gate",
            backend,
            [
                (
                    "return r.localDiscoveryGateLocked()",
                    "return r.discoveryUnknown.Load()",
                )
            ],
            recovery,
            "unsampled gate:",
        ),
        (
            "broad_unsampled_gate",
            backend,
            [
                (
                    "return r.localDiscoveryGateLocked()",
                    "return r.discoveryUnknown.Load() || (r.discoveryMode && !r.allSampledLocked())",
                ),
                (
                    "if r.localDiscoveryGateLocked() {",
                    "if r.discoveryUnknown.Load() || (r.discoveryMode && !r.allSampledLocked()) {",
                ),
            ],
            addition,
            "addition interrupted healthy request:",
        ),
        (
            "short_health_window",
            backend,
            [
                (
                    "return r.interval + HealthCheckTimeout + 2*CapacityReportTimeout + HealthFreshnessMargin",
                    "return 2 * r.interval",
                )
            ],
            hung,
            "known N=0 want1",
        ),
        (
            "serial_old_health_loop",
            backend,
            [
                (
                    "checks.Go(func() { r.check(ctx, backend) })",
                    "r.check(ctx, backend)",
                ),
                (
                    "return r.interval + HealthCheckTimeout + 2*CapacityReportTimeout + HealthFreshnessMargin",
                    "return 2 * r.interval",
                ),
            ],
            hung,
            "known N=0 want1",
        ),
        (
            "healthy_but_unready_gate",
            backend,
            [("else if b.Healthy() && b.Ready() {", "else if b.Healthy() {")],
            recovery,
            "partial healthy-but-unready sample opened gate",
        ),
        (
            "rehearsal_broad_addition_gate",
            backend,
            [
                (
                    "return r.localDiscoveryGateLocked()",
                    "return r.discoveryUnknown.Load() || (r.discoveryMode && !r.allSampledLocked())",
                )
            ],
            ttl + "/shortTTL=false",
            "rehearsal HTTP/SSE gateway=0 want=completed",
        ),
        (
            "rehearsal_wrong_direct_destination",
            handler,
            [
                (
                    'backend.URL.JoinPath("v1/chat/completions").String()',
                    '"http://10.0.0.3:8000/v1/chat/completions"',
                )
            ],
            rollout,
            "ingress live content before drain",
        ),
        (
            "rehearsal_omit_reservation_release",
            handler,
            [
                (
                    "func (g *Gateway) bestEffortRelease(tenantID, reservationID, requestID string) {",
                    "func (g *Gateway) bestEffortRelease(tenantID, reservationID, requestID string) {\n return",
                )
            ],
            rollout,
            "rehearsal reservation leak after startup",
        ),
        (
            "rehearsal_partial_known_report",
            backend,
            [
                (
                    "known := !r.discoveryUnknown.Load() && r.allSampledLocked()",
                    "known := !r.discoveryUnknown.Load()",
                )
            ],
            rollout,
            "rehearsal report completeness",
        ),
        (
            "rehearsal_wrong_capacity_unit",
            lua,
            [
                (
                    "local unit = tonumber(ARGV[11]) + tonumber(ARGV[12])",
                    "local unit = tonumber(ARGV[11]) - tonumber(ARGV[12])",
                )
            ],
            ttl,
            "rehearsal B/TTL startup agreement complete",
        ),
        (
            "rehearsal_expired_reports_admit",
            lua,
            [
                (
                    "if not fresh then return result('capacity_reports_expired', 0, 0) end",
                    "if not fresh and capacity == 0 then return result('capacity_reports_expired', 0, 0) end",
                )
            ],
            ttl + "/shortTTL=true",
            "rehearsal B/TTL addition step 0",
        ),
        (
            "rehearsal_missing_after_admit_counter",
            handler,
            [
                (
                    "g.metrics.discoveryUnknownAfterAdmit.Add(1)\n\t\tg.writeError",
                    "// mutant: counter omitted\n\t\tg.writeError",
                )
            ],
            rollout,
            "rehearsal event distribution discovery-after-admit-race",
        ),
        (
            "rehearsal_terminating_still_routable",
            discovery,
            [
                (
                    "if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || (endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {\n\t\t\t\texcluded",
                    "if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready {\n\t\t\t\texcluded",
                ),
                (
                    "if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready || (endpoint.Conditions.Terminating != nil && *endpoint.Conditions.Terminating) {\n\t\t\t\tcontinue",
                    "if endpoint.Conditions.Ready == nil || !*endpoint.Conditions.Ready {\n\t\t\t\tcontinue",
                ),
            ],
            rollout,
            "rehearsal terminating membership did not exclude old UID",
        ),
        (
            "rehearsal_revalidate_established_stream",
            handler,
            [
                (
                    "if event.done {\n\t\t\tif !finished",
                    'if event.done {\n\t\t\tif !g.registry.CanDispatch(backend) { g.interrupt(response, requestID, "stream interrupted"); return }\n\t\t\tif !finished',
                )
            ],
            rollout,
            "rehearsal drain completion",
        ),
        (
            "rehearsal_incomplete_SSE_success",
            handler,
            [("if !finished || !usageSeen {", "if false {")],
            rollout,
            "rehearsal HTTP/SSE gateway=0 want=stream_interrupted",
        ),
        (
            "rehearsal_rollback_inherits_UID_health",
            backend,
            [
                (
                    "old.ID == backend.ID && old.Generation == backend.Generation && old.URL.String() == backend.URL.String()",
                    "old.ID == backend.ID && old.URL.String() == backend.URL.String()",
                )
            ],
            rollout,
            "rehearsal rollback inherited UID health",
        ),
        (
            "missing_revalidation_counter",
            handler,
            [
                (
                    "g.metrics.backendChangedAfterAdmit.Add(1)",
                    "// mutant: counter omitted",
                )
            ],
            counter,
            "dispatch or wrong counters",
        ),
    ]
    with tempfile.TemporaryDirectory(prefix="m5-admission-mutants-") as directory:
        work = Path(directory)
        for name in ("go.mod", "go.sum"):
            shutil.copy2(root / name, work / name)
        shutil.copytree(root / "internal", work / "internal")
        env = os.environ.copy()
        env.setdefault("GOMODCACHE", str(root / ".cache" / "go-mod"))
        env.update(GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local")

        def run(pattern: str) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    "go",
                    "test",
                    "-count=1",
                    "-v",
                    "./internal/admission"
                    if withheld in pattern
                    else "./internal/gateway",
                    "-run",
                    pattern,
                ],
                cwd=work,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=120,
                check=False,
            )

        result = run(f"^({recovery}|{hung}|{counter}|{addition}|{ttl}|{rollout})$")
        if result.returncode != 0:
            raise SystemExit("baseline failed:\n" + result.stdout + result.stderr)
        print("BASELINE PASS", flush=True)
        result = run(f"^{withheld}$")
        if result.returncode != 0 or f"--- PASS: {withheld}" not in result.stdout:
            raise SystemExit(
                "coordinator baseline failed or skipped:\n"
                + result.stdout
                + result.stderr
            )
        print("COORDINATOR BASELINE PASS", flush=True)
        for name, filename, replacements, pattern, expected in mutations:
            original = (work / filename).read_text(encoding="utf-8")
            source = original
            for old, new in replacements:
                if source.count(old) != 1:
                    raise SystemExit(f"{name}: mutation point missing or ambiguous")
                source = source.replace(old, new, 1)
            try:
                (work / filename).write_text(source, encoding="utf-8")
                result = run(f"^{pattern}$")
                if result.returncode == 0 or expected not in result.stdout:
                    raise SystemExit(
                        f"{name}: survived or failed for wrong reason:\n{result.stdout}{result.stderr}"
                    )
                evidence = next(
                    line.strip()
                    for line in result.stdout.splitlines()
                    if expected in line
                )
                print(f"KILLED {name}: {evidence}", flush=True)
            finally:
                (work / filename).write_text(original, encoding="utf-8")


if __name__ == "__main__":
    main()
