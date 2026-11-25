-- Shared key order: admitted, admitted-at, progress, terminal, events,
-- discrepancies, deadlines, open-deadlines, retired.
local recovery_grace_ms = 60 * 1000
local correction_window_ms = 24 * 60 * 60 * 1000

local function store_time_ms()
  local clock = redis.call('TIME')
  return tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
end

local function record_discrepancy(key, event, cause)
  redis.call('HSETNX', KEYS[6], event .. '|' .. cause, cjson.encode({
    tenant_id = string.match(key, '^([^:]+):'), attempt_key = key, cause = cause
  }))
end

local function usage_counts(key, event, dispatched, point, completed)
  local runtime = point and point.runtime
  local estimate = point and point.estimate
  local mismatch = runtime and estimate and
    (runtime.prompt ~= estimate.prompt or runtime.completion ~= estimate.completion)
  if mismatch then record_discrepancy(key, event, 'usage_estimate_mismatch') end
  local function token(field)
    if not dispatched then return {classification = 'exact', tokens = 0, source = 'no_dispatch'} end
    if not runtime then return {classification = 'unknown', source = 'unavailable'} end
    local classification = 'observed_partial'
    if mismatch then classification = 'quarantined'
    elseif completed then classification = 'exact' end
    return {classification = classification, tokens = runtime[field], source = 'runtime_usage'}
  end
  return token('prompt'), token('completion')
end

local function terminal_row(key, request, owner, state, pins, outcome, committed, event)
  local tenant, reservation = string.match(key, '^([^:]+):(.+)$')
  local point = state and state.checkpoint
  local prompt, completion = usage_counts(key, event, state ~= nil, point, outcome == 'completed')
  local deadline = tonumber(redis.call('ZSCORE', KEYS[7], key))
  return {
    tenant_id = tenant, reservation_id = reservation, request_id = request,
    owner_epoch = owner, admitted_unix_ms = tonumber(redis.call('HGET', KEYS[2], key)),
    admission_deadline_unix_ms = deadline and deadline > 0 and deadline or nil,
    pins = state and state.pins or pins, dispatch_intent = state ~= nil,
    stream_committed = committed, outcome = outcome, version = 1, checkpoint = point,
    prompt = prompt, completion = completion
  }
end
