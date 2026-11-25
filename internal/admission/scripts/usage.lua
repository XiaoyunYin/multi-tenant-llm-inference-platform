-- The admitted hash and its values are the unchanged slice-1 join.
local key, request, owner = ARGV[1], ARGV[2], ARGV[3]
local operation, event, fingerprint = ARGV[4], ARGV[5], ARGV[6]
local body = cjson.decode(ARGV[7])
local admitted = redis.call('HGET', KEYS[1], key)
local progress_raw = redis.call('HGET', KEYS[3], key)
local terminal_raw = redis.call('HGET', KEYS[4], key)
local prior_event = redis.call('HGET', KEYS[5], event)
local deadline = tonumber(redis.call('ZSCORE', KEYS[7], key))
redis.call('HLEN', KEYS[6])
redis.call('ZSCORE', KEYS[8], key)

local function conflict(reason, status)
  record_discrepancy(key, event .. '|' .. fingerprint, reason)
  return {status or 'conflict', ''}
end

if admitted ~= request then
  if operation == 'correction' and redis.call('HGET', KEYS[9], key) == request then
    return conflict('late_correction_retired', 'window_closed')
  end
  return {'binding', ''}
end

local row = terminal_raw and cjson.decode(terminal_raw) or nil
if operation == 'correction' then
  if not row or row.tenant_id ~= body.tenant_id or row.reservation_id ~= body.reservation_id or
    row.request_id ~= request or row.owner_epoch ~= owner then return {'binding', ''} end
  if row.correction_fingerprint == fingerprint then return {'replayed', terminal_raw} end
  for _, version in ipairs(row.history or {}) do
    if version.correction_fingerprint == fingerprint then return {'replayed', terminal_raw} end
  end
  local arrived = store_time_ms()
  if not deadline or deadline <= 0 then return conflict('correction_deadline_unavailable', 'window_closed') end
  if arrived > deadline + correction_window_ms then
    return conflict('late_correction_after_window', 'window_closed')
  end
  if row.version ~= body.expected_version then return conflict('correction_version_conflict') end
  if not row.dispatch_intent then return conflict('correction_without_dispatch') end
  if row.checkpoint and row.checkpoint.sequence >= body.checkpoint.sequence then
    return conflict('stale_correction_checkpoint')
  end
  local previous = cjson.decode(terminal_raw)
  previous.history = nil
  row.history = row.history or {}
  table.insert(row.history, previous)
  row.version = row.version + 1
  row.checkpoint = body.checkpoint
  row.admission_deadline_unix_ms = deadline
  row.correction = {arrival_unix_ms = arrived, evidence_sha256 = body.evidence_sha256, reason = body.reason}
  row.correction_fingerprint = fingerprint
  row.prompt, row.completion = usage_counts(key, event .. '|' .. fingerprint, true, row.checkpoint, row.outcome == 'completed')
  local updated = cjson.encode(row)
  redis.call('HSET', KEYS[4], key, updated)
  return {'written', updated}
end

local state = progress_raw and cjson.decode(progress_raw) or nil
if (row and row.outcome == 'owner_lost') or (state and state.fenced) then
  return conflict('owner_epoch_fenced')
end
if operation == 'terminal' and row then
  if row.event_fingerprint == fingerprint then return {'replayed', terminal_raw} end
  return conflict('terminal_payload_conflict')
end
if prior_event then
  if prior_event ~= fingerprint then return conflict('event_payload_conflict') end
  return {'replayed', terminal_raw or ''}
end
if row then return conflict('terminal_already_written') end
if state and state.owner_epoch ~= owner then return conflict('owner_epoch_conflict') end

if operation == 'dispatch' then
  if state then
    if state.dispatch_fingerprint == fingerprint then return {'replayed', ''} end
    return conflict('dispatch_already_written')
  end
  state = {owner_epoch = owner, pins = body.pins, dispatch_fingerprint = fingerprint}
  redis.call('HSET', KEYS[3], key, cjson.encode(state))
elseif operation == 'checkpoint' then
  if not state then return {'binding', ''} end
  if state.checkpoint and state.checkpoint.sequence >= body.checkpoint.sequence then
    if state.checkpoint_fingerprint == fingerprint then return {'replayed', ''} end
    return conflict('stale_checkpoint')
  end
  state.checkpoint = body.checkpoint
  state.checkpoint_fingerprint = fingerprint
  redis.call('HSET', KEYS[3], key, cjson.encode(state))
elseif operation == 'terminal' then
  if not state and (body.outcome == 'completed' or body.stream_committed) then return {'binding', ''} end
  if state and (state.pins.model ~= body.pins.model or state.pins.model_pin ~= body.pins.model_pin or
    state.pins.engine ~= body.pins.engine or state.pins.tokenizer ~= body.pins.tokenizer) then
    return conflict('pins_conflict')
  end
  row = terminal_row(key, request, owner, state, body.pins, body.outcome, body.stream_committed == true,
    event .. '|' .. fingerprint)
  row.event_fingerprint = fingerprint
  local result = cjson.encode(row)
  redis.call('HSET', KEYS[4], key, result)
  redis.call('ZREM', KEYS[8], key)
  return {'written', result}
else
  return {'binding', ''}
end
redis.call('HSET', KEYS[5], event, fingerprint)
return {'written', ''}
