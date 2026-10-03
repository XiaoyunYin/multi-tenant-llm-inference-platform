# Integration tests

Cross-process integration coverage lives with the Python test harness so it is discovered by the shared local/CI command:

- `python/tests/test_gateway_integration.py` compiles the Go gateway and exercises the streaming contract against real Python fake-backend processes.
- `python/tests/test_admission_process_integration.py` requires `REDIS_TEST_ADDR`, launches two independent gateway processes, and exercises shared admission, noisy-neighbor isolation, coordinator connectivity faults, abrupt process death, and terminal reconciliation.

Run the complete CPU suite with a disposable Redis endpoint:

```powershell
$env:REDIS_TEST_ADDR='127.0.0.1:6379'
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\check.ps1 -Suite all
```

The process-admission class is skipped explicitly when `REDIS_TEST_ADDR` is absent; a skip is not evidence that shared admission passed.
