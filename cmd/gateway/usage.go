package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"
)

func startUsageSweep(store *admission.RedisCoordinator, logger *slog.Logger) (func(), error) {
	setup, cancelSetup := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelSetup()
	if err := store.PrepareUsageMaintenance(setup); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			sweepCtx, cancelSweep := context.WithTimeout(ctx, time.Second)
			_, err := store.SweepUsage(sweepCtx, 64)
			cancelSweep()
			if err != nil && ctx.Err() == nil {
				logger.Error("metering recovery sweep did not complete")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }, nil
}

func runUsageCommand(store *admission.RedisCoordinator, args []string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := usageCommand(ctx, store, args, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func usageCommand(ctx context.Context, store *admission.RedisCoordinator, args []string, out io.Writer) error {
	if len(args) == 2 && args[0] == "export" {
		data, digest, err := store.ExportUsageCohort(ctx, 128)
		if err != nil {
			return err
		}
		if data == nil {
			_, err := fmt.Fprintln(out, "no closed usage cohort")
			return err
		}
		if err := saveUsageArchive(args[1], data); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, digest)
		return err
	}
	if len(args) == 3 && args[0] == "retire" {
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		count, err := store.RetireUsageCohort(ctx, data, args[2])
		if err == nil {
			_, err = fmt.Fprintln(out, count)
		}
		return err
	}
	if len(args) == 3 && args[0] == "correct" {
		correction, err := loadUsageCorrection(args[1], args[2])
		if err != nil {
			return err
		}
		row, err := store.CorrectUsage(ctx, correction)
		if err == nil {
			_, err = fmt.Fprintln(out, row.Version)
		}
		return err
	}
	return errors.New("usage maintenance: export <file>, retire <file> <sha256>, or correct <reviewed-json> <evidence-file>")
}

func saveUsageArchive(path string, data []byte) error {
	archive, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := archive.Write(data)
	return errors.Join(writeErr, archive.Sync(), archive.Close())
}

func loadUsageCorrection(path, evidencePath string) (admission.UsageCorrection, error) {
	var correction admission.UsageCorrection
	file, err := os.Open(path)
	if err != nil {
		return correction, err
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&correction); err != nil {
		return correction, errors.New("invalid reviewed usage correction JSON")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return correction, errors.New("unexpected data after reviewed usage correction")
	}
	evidence, err := os.Open(evidencePath)
	if err != nil {
		return correction, err
	}
	defer evidence.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, evidence); err != nil {
		return correction, err
	}
	if fmt.Sprintf("%x", digest.Sum(nil)) != correction.EvidenceSHA256 {
		return correction, admission.ErrUsageBinding
	}
	return correction, nil
}
