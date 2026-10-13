// Deterministic, no-network host-input fixture. This is not a digest encoder or
// a vLLM observational patch. Enumerate the complete registered physical/owner
// populations and emit host-computed numerical source observations for Python's
// real checkpoint serializer. Nothing is gzip/base64 encoded here.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type snapshot struct {
	Slot         int       `json:"slot"`
	Observed     uint64    `json:"observed_ns"`
	Counts       [8]uint64 `json:"counts"` // cached, shared, nonshared, evictable, capacity, null, active, event-live
	OwnerLinks   uint64    `json:"owner_links"`
	Unscheduled  uint64    `json:"unscheduled"`
	Queue        uint64    `json:"queue"`
	Valid        bool      `json:"valid"`
	Gap          uint64    `json:"gap"`
	Drops        uint64    `json:"drops"`
	ActiveLimit  int       `json:"active_limit"`
	SharedLimit  int       `json:"shared_limit"`
	Reset        uint64    `json:"reset"`
	Phase        uint64    `json:"phase"`
	Replay       uint64    `json:"replay"`
	Duplicate    uint64    `json:"duplicate"`
	Ambiguous    uint64    `json:"ambiguous"`
	Orphan       uint64    `json:"orphan"`
	MissingOwner uint64    `json:"missing_owner"`
	Unexplained  uint64    `json:"unexplained"`
	Temporary    uint64    `json:"temporary"`
	Fence        uint64    `json:"fence"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: stage_c_host_fixture OUTPUT.json")
	}
	started := time.Now()
	const base uint64 = 8731982100000000
	const blocks = 3891
	var physicalRows, ownerRows, sidebandRows uint64
	var mix uint64 = 470150
	next := func() uint64 { mix ^= mix << 13; mix ^= mix >> 7; mix ^= mix << 17; return mix }
	commitment := sha256.New()
	rows := make([]snapshot, 0, 48001)
	// Native cached keys and token identities have their registered full widths.
	var pools [10][blocks][96]byte
	for epoch := range pools {
		for physical := range pools[epoch] {
			for part := 0; part < 3; part++ {
				digest := sha256.Sum256([]byte(fmt.Sprintf("pool/%d/%d/%d", epoch, physical, part)))
				copy(pools[epoch][physical][part*32:], digest[:])
			}
		}
	}
	var scalarFrame [256]byte
	visit := func(values ...uint64) {
		for i, value := range values {
			binary.LittleEndian.PutUint64(scalarFrame[i*8:], value)
		}
		commitment.Write(scalarFrame[:len(values)*8])
	}
	for slot := 0; slot <= 48000; slot++ {
		row := snapshot{Slot: slot, Observed: base + uint64(slot)*100000000 + next()%10000, Queue: next() % 1000000, Valid: true}
		cached := uint64(500 + next()%3391)
		epoch := 0
		if slot >= 10000 && slot < 24000 {
			epoch = 1 + (slot/1000-10)/2
		} else if slot >= 24000 && slot < 27000 {
			epoch = 7
		} else if slot >= 27000 && slot < 36000 {
			epoch = 8
		} else if slot >= 36000 {
			epoch = 9
		}
		row.Reset = uint64(epoch)
		if slot >= 10000 && slot < 24000 {
			row.Phase = uint64(slot/1000%2) + 1
		}
		if slot >= 36000 {
			row.Phase = uint64((slot-36000)/3000%2) + 1
		}
		row.Counts[0], row.Counts[7] = cached, cached
		if slot >= 27000 && slot <= 45000 {
			switch slot % 97 {
			case 0:
				row.Gap = 1
				row.Valid = false
			case 1:
				row.Drops = 1
				row.Valid = false
			case 2:
				row.Duplicate = 1
				row.Valid = false
			case 3:
				row.Replay = 1
				row.Valid = false
			case 4:
				row.Ambiguous = 1
				row.Valid = false
			case 5:
				row.Orphan = 1
				row.Valid = false
			case 6:
				row.MissingOwner = 1
				row.Valid = false
			case 7:
				row.Unexplained = 1
				row.Valid = false
			case 8:
				row.Temporary = 1
				row.Fence = 1
			}
			// One reserved-null block, with 128 real holders (including unscheduled
			// and non-cohort holders), each retaining all 512 block positions.
			active := 512 + int(next()%3378)
			if active%7 == 0 {
				active++
			}
			// Frozen W identities within each reset epoch. Pin membership changes
			// with the live owner set, never by changing W after seeing a result.
			sharedLimit := 1537 + epoch*31
			if sharedLimit > active {
				sharedLimit = active
			}
			row.ActiveLimit, row.SharedLimit = active, sharedLimit
			var activeSet, sharedSet [blocks]bool
			var ownerCounts [blocks]uint64
			for owner := 0; owner < 128; owner++ {
				ownerIdentity := sha256.Sum256([]byte(fmt.Sprintf("owner/%d/%d", slot, owner)))
				commitment.Write(ownerIdentity[:])
				if owner%3 != 0 {
					row.Unscheduled++
				}
				for position := 0; position < 512; position++ {
					physical := 1 + (owner*13+position*7+slot)%active
					activeSet[physical] = true
					ownerCounts[physical]++
					if physical <= sharedLimit && position < 384 {
						sharedSet[physical] = true
					}
					// Every link's key, holder and scheduled/non-cohort branch is
					// visited; duplicate physical ownership is not discarded.
					mix ^= uint64(physical)*0x9e3779b97f4a7c15 + uint64(owner*512+position)
					// Full owner keys, explicit probe/non-load holders and unscheduled
					// status are source inputs; only numerical projections survive.
					kind := uint64(0)
					if owner >= 112 {
						kind = 2
					} else if owner >= 96 {
						kind = 1
					}
					scheduled, inW, ownerStatus, nulls := uint64(0), uint64(0), uint64(0), uint64(0)
					if owner%3 == 0 {
						scheduled = 1
					}
					if physical <= sharedLimit && position < 384 {
						inW = 1
					}
					if position >= 384 {
						ownerStatus, nulls = 1, 1<<11
					}
					if epoch == 9 && owner >= 60 {
						kind = 2
					}
					if kind != 0 {
						ownerStatus, nulls = 3, nulls|(1<<4)
					}
					requestStart := 10359
					if slot >= 30000 && slot < 33000 {
						requestStart = 10539
					} else if slot >= 33000 && slot < 36000 {
						requestStart = 11259
					} else if slot >= 36000 && slot < 39000 {
						requestStart = 14139
					} else if slot >= 39000 {
						requestStart = 14199
					}
					if row.MissingOwner != 0 && owner == 0 {
						ownerStatus = 5
					}
					visit(uint64(slot), uint64(owner), kind, uint64(requestStart+owner%96), uint64(epoch), 0, 0, uint64(position), uint64(physical), scheduled, inW, ownerStatus, row.MissingOwner, nulls)
					commitment.Write(ownerIdentity[:])
					if position < 384 {
						commitment.Write(pools[epoch][physical][64:])
					}
					ownerRows++
				}
			}
			var activeN, sharedN, evictable uint64
			for physical := 0; physical < blocks; physical++ {
				// Native keys are opaque 64-byte values; token digests are 32 bytes.
				// Vary by physical identity and reset epoch, preserving repeated
				// identities within an epoch as an actual live set does.
				cachedFlag, wFlag, nullFlag, freeFlag, membership := uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)
				if physical > 0 && uint64(physical) <= cached {
					cachedFlag = 1
				}
				if sharedSet[physical] {
					wFlag, membership = 1, 1
				}
				if physical == 0 {
					nullFlag, membership = 1, 3
				} else {
					keyPhysical := physical
					if row.Ambiguous != 0 && physical == 2 {
						keyPhysical = 1
					}
					commitment.Write(pools[epoch][keyPhysical][:])
				}
				if !activeSet[physical] && cachedFlag == 0 && physical != 0 {
					freeFlag = 1
				}
				// All 24 registered columns are framed; opaque key/digest fields
				// above have 64/32 bytes, with explicit null for the reserved block.
				cow, fence, unexplained, joinStatus := uint64(0), uint64(0), uint64(0), uint64(0)
				if physical == 1 {
					cow, fence, unexplained = row.Temporary, row.Fence, row.Unexplained
				}
				if row.Ambiguous != 0 && physical == 2 {
					joinStatus = 1
				}
				if unexplained != 0 {
					joinStatus = 4
				}
				visit(uint64(slot), uint64(epoch), 0, 0, uint64(physical), uint64(epoch), cachedFlag, uint64(slot), uint64(slot), 0, uint64(slot), wFlag, membership, ownerCounts[physical], ownerCounts[physical]+cow+fence+unexplained, cow, fence, nullFlag, freeFlag, cachedFlag, joinStatus, row.Unexplained, nullFlag)
				if activeSet[physical] {
					activeN++
				}
				if sharedSet[physical] {
					sharedN++
				}
				if physical > 0 && uint64(physical) <= cached && !activeSet[physical] {
					evictable++
				}
				physicalRows++
			}
			nonshared := activeN - sharedN
			row.Counts = [8]uint64{cached, sharedN, nonshared, evictable, blocks - nonshared, 1, activeN, cached}
			row.OwnerLinks = 128 * 512
			// Gap, reset, replay, duplicate, pending and loss paths are explicit
			// invalid observations, never substituted valid zeros.
			if slot%997 == 0 {
				row.Valid = false
				row.Gap = 1
			}
			if slot%991 == 0 {
				row.Valid = false
				row.Drops = 1
			}
			sidebandRows++
			status := uint64(0)
			if row.Gap != 0 {
				status = 4
			} else if row.Drops != 0 {
				status = 3
			} else if row.Duplicate != 0 {
				status = 5
			} else if row.Replay != 0 {
				status = 6
			}
			visit(uint64(slot-27000), uint64(slot), uint64(epoch), 0, uint64(slot), row.Observed-10000, uint64(slot), row.Observed-5000, row.Observed, uint64(slot-1), row.Gap, row.Duplicate, row.Replay, row.Drops, status, 0)
		}
		var frame [32]byte
		binary.LittleEndian.PutUint64(frame[:8], uint64(slot))
		binary.LittleEndian.PutUint64(frame[8:16], row.Observed)
		binary.LittleEndian.PutUint64(frame[16:24], mix)
		binary.LittleEndian.PutUint64(frame[24:], row.OwnerLinks)
		commitment.Write(frame[:])
		rows = append(rows, row)
		// Complete descriptor population, including explicit unavailable owner
		// and queue fields outside the observational interval.
		patched, unavailable := uint64(0), uint64(0)
		if slot >= 27000 && slot <= 45000 {
			patched = 1
		} else {
			unavailable = 1
		}
		visit(uint64(slot), uint64(slot), patched*2, 0, uint64(epoch), 0, 0, uint64(slot), row.Observed, row.Observed-20000, row.Observed, 20000, 10000, 0, row.Drops, blocks, patched, uint64(slot), uint64(slot), row.Observed-1000, 1000, row.Queue, 1000, unavailable)
	}
	if physicalRows != 70041891 || ownerRows != 1179713536 || sidebandRows != 18001 {
		panic("fixture conservation failed")
	}
	// Exercise the conservative manifest capacity independently of the tighter
	// phase-specific 5,160,576 full blocks. These are host-only fixed-width rows.
	var manifestRows uint64
	for request := 0; request < 14259; request++ {
		for position := 0; position < 384; position++ {
			var identities [96]byte
			for part := 0; part < 3; part++ {
				digest := sha256.Sum256([]byte(fmt.Sprintf("manifest/%d/%d/%d", request, position, part)))
				copy(identities[part*32:], digest[:])
			}
			visit(uint64(request), uint64(position), uint64(position%2))
			commitment.Write(identities[:])
			manifestRows++
		}
	}
	file, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	err = json.NewEncoder(file).Encode(map[string]any{
		"schema": "stage-c-host-ceiling-fixture.v1", "snapshot_rows": 48001,
		"physical_join_rows": physicalRows, "owner_link_rows": ownerRows, "sideband_rows": sidebandRows,
		"manifest_capacity_rows": manifestRows,
		"source_visit_sha256":    hex.EncodeToString(commitment.Sum(nil)), "mix": mix,
		"duration_s": time.Since(started).Seconds(), "snapshots": rows,
		"source_field_counts": map[string]int{"snapshot_exact.v1": 24, "snapshot_live_set_join.v1": 24, "snapshot_request_owner.v1": 15, "snapshot_sideband.v1": 16},
		"limitations":         "Synthetic source-row traversal and numerical conservation fixture; not a vLLM producer, source-fitness proof or measured engine behavior. Source hash does not recover physical, owner or matched-array members.",
	})
	if err != nil {
		panic(err)
	}
	if err = file.Sync(); err != nil {
		panic(err)
	}
}
