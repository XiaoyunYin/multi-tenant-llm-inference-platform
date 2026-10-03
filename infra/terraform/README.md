# Terraform infrastructure

`pilot/` contains the bounded INF-011 single-GPU EC2 stack. Its default offline plan creates zero resources. A paid plan or apply requires all budget variables, a configured AWS identity, and a non-offline provider; the wrapper additionally requires an exact confirmation phrase before apply.

Validate the stack without AWS credentials or paid resources:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\inf011-pilot.ps1 -Action Validate
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\inf011-pilot.ps1 -Action PlanOffline
```

Do not use `Apply` until the budget gate in `docs/INF011_READINESS.md` is marked approved. State is local and ignored for this disposable pilot; the later EKS stack owns remote-state design.
