import copy
import random
import struct
import unittest

from remainder_fixtures import measurement_source

from inference_platform.stage_c_registered import RetentionError
from inference_platform.stage_c_resources import (
    EVICTION_SCHEMA,
    GATEWAY_SCHEMA,
    HIST_SCHEMA,
    cpu_values,
    eviction_summary,
    gateway_summary,
    histogram_summary,
    pack_fixed,
    unpack_fixed,
)


class ResourceSummaryTest(unittest.TestCase):
    def test_full_cadence_requires_wide_rss_integral(self):
        source = measurement_source(
            1, 8_731_982_100_000_000, random.Random(47), True, sample_count=48001
        )
        row = gateway_summary(source["gateway_samples"])
        self.assertEqual(len(source["gateway_samples"]), 48000)
        self.assertEqual(row["pair_n"], 47989)
        self.assertEqual(row["excluded_pair_n"], 10)
        self.assertGreater(row["rss_integral"], 2**64)
        self.assertEqual(
            unpack_fixed(pack_fixed(row, GATEWAY_SCHEMA, 176, 4), GATEWAY_SCHEMA, 176, 4), row
        )

    def test_pid_decrease_gap_and_excluded_pairs(self):
        source = measurement_source(1, 8_731_982_100_000_000, random.Random(18), False)
        samples = source["gateway_samples"]
        row = gateway_summary(samples)
        self.assertEqual(row["pid_change_n"], 2)
        self.assertEqual(row["cpu_decrease_n"], 1)
        self.assertEqual(row["missed_slot_n"], 1)
        self.assertEqual(row["non_monotonic_n"], 1)
        self.assertEqual((row["missing_n"], row["access_error_n"]), (1, 1))
        self.assertEqual(row["pair_n"] + row["excluded_pair_n"], len(samples) - 1)
        pairs = []
        for before, after in zip(samples, samples[1:], strict=False):
            if (before["slot"], after["slot"]) in (
                (0, 1),
                (1, 2),
                (4, 5),
                (6, 7),
                (7, 8),
                (10, 11),
                (11, 12),
                (14, 15),
            ):
                pairs.append((before, after))
        # Independently enumerate the eight usable pairs in this 20-slot fixture.
        self.assertEqual(row["pair_n"], len(pairs))
        self.assertEqual(row["cpu_ticks"], sum(b["cpu_ticks"] - a["cpu_ticks"] for a, b in pairs))
        self.assertEqual(
            row["duration_ns"], sum(b["monotonic_ns"] - a["monotonic_ns"] for a, b in pairs)
        )
        self.assertEqual(
            row["rss_integral"],
            sum(a["rss_bytes"] * (b["monotonic_ns"] - a["monotonic_ns"]) for a, b in pairs),
        )
        recovered = unpack_fixed(pack_fixed(row, GATEWAY_SCHEMA, 176, 4), GATEWAY_SCHEMA, 176, 4)
        self.assertEqual(recovered, row)
        values = cpu_values(row, 100)
        self.assertEqual(
            values["level_mean_cores"], row["cpu_ticks"] * 1e9 / 100 / row["duration_ns"]
        )
        self.assertEqual(values["one_tick_per_100ms_cores"], 0.1)
        self.assertEqual(
            row["valid_n"]
            + row["missing_n"]
            + row["access_error_n"]
            + row["non_monotonic_n"]
            + row["identity_mismatch_n"],
            row["sample_n"],
        )

    def test_restart_after_missing_sample_is_counted_and_reconciles(self):
        def sample(slot, pid, start_ticks, cpu_ticks, status="ok"):
            return dict(
                slot=slot,
                pid=pid,
                start_ticks=start_ticks,
                monotonic_ns=10**16 + slot * 100_000_000 if status == "ok" else None,
                cpu_ticks=cpu_ticks if status == "ok" else None,
                rss_bytes=100_000_000 if status == "ok" else None,
                peak_rss_bytes=100_000_000 if status == "ok" else None,
                status=status,
            )

        samples = [sample(0, 10, 100, 100), sample(1, 10, 100, 110)]
        samples.append(sample(2, None, None, None, "missing"))
        samples.extend(sample(slot, 20, 200, 120 + slot) for slot in range(3, 40))
        row = gateway_summary(samples)
        self.assertEqual((row["valid_n"], row["missing_n"]), (2, 1))
        self.assertEqual(row["identity_mismatch_n"], 37)
        self.assertEqual(row["pid_change_n"], 0)
        self.assertEqual(row["sample_n"], 40)
        self.assertEqual(
            row["valid_n"]
            + row["missing_n"]
            + row["access_error_n"]
            + row["non_monotonic_n"]
            + row["identity_mismatch_n"],
            row["sample_n"],
        )
        recovered = unpack_fixed(pack_fixed(row, GATEWAY_SCHEMA, 176, 4), GATEWAY_SCHEMA, 176, 4)
        self.assertEqual(recovered, row)
        bad = dict(row, sample_n=row["sample_n"] - 1)
        with self.assertRaisesRegex(RetentionError, "gateway_resources.sample_n"):
            pack_fixed(bad, GATEWAY_SCHEMA, 176, 4)

    def test_start_identity_missing_and_integer_overflows(self):
        source = measurement_source(1, 10**16, random.Random(12), False)
        source["gateway_samples"][3]["pid"] -= 1
        source["gateway_samples"][3]["start_ticks"] += 1
        self.assertEqual(gateway_summary(source["gateway_samples"])["pid_change_n"], 2)
        missing = gateway_summary([])
        self.assertEqual(missing["status"], 2)
        self.assertIsNone(missing["rss_max"])
        for name, value in (("pid", 2**32), ("cpu_ticks", 2**64), ("rss_bytes", -1)):
            bad = copy.deepcopy(source["gateway_samples"])
            bad[0][name] = value
            with self.assertRaises(RetentionError):
                gateway_summary(bad)
        for ticks in (0, -1, 100.0):
            with self.assertRaises(RetentionError):
                cpu_values(missing, ticks)

    def test_histogram_exact_sum_bits_reset_missing_and_overflow(self):
        source = measurement_source(1, 10**16, random.Random(12), False)["lookup"]
        row = histogram_summary(source)
        bits = struct.unpack(
            "<Q", struct.pack("<d", source["after"]["sum"] - source["before"]["sum"])
        )[0]
        self.assertEqual(row["sum_bits"], bits)
        self.assertEqual(unpack_fixed(pack_fixed(row, HIST_SCHEMA, 64, 2), HIST_SCHEMA, 64, 2), row)
        for flag, status in (("reset", 1), ("missing", 2)):
            bad = copy.deepcopy(source)
            bad[flag] = True
            row = histogram_summary(bad)
            self.assertEqual(row["status"], status)
            self.assertTrue(all(value is None for key, value in row.items() if key != "status"))
        for value in (float("inf"), -1.0):
            bad = copy.deepcopy(source)
            bad["after"]["sum"] = value
            with self.assertRaises(RetentionError):
                histogram_summary(bad)
        bad = copy.deepcopy(source)
        bad["after"]["buckets"] = [2**32 + 200000] * 11
        bad["after"]["count"] = bad["after"]["buckets"][-1]
        with self.assertRaises(RetentionError):
            histogram_summary(bad)

    def test_eviction_dedup_coverage_gap_reset_and_missing(self):
        identity = "ac" * 32
        bins = [
            dict(
                second_ns=10**16 + i * 10**9,
                removed_identities=[identity] * 2,
                valid=True,
                gap=i == 1,
                reset=i == 2,
            )
            for i in range(4)
        ]
        row = eviction_summary(bins)
        self.assertEqual(
            (row["removed"], row["covered_seconds"], row["gap_seconds"], row["flags"]), (2, 2, 2, 3)
        )
        self.assertEqual(row["max_per_second"], 1)
        self.assertEqual(row["max_time_ns"], bins[0]["second_ns"])
        self.assertEqual(
            unpack_fixed(pack_fixed(row, EVICTION_SCHEMA, 32, 2), EVICTION_SCHEMA, 32, 2), row
        )
        self.assertEqual(eviction_summary([])["status"], 2)
        with self.assertRaises(RetentionError):
            eviction_summary(bins + [bins[0]])


if __name__ == "__main__":
    unittest.main()
