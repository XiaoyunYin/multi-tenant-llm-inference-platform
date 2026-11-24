-- The admitted hash and its values are the unchanged slice-1 join.
local key, request, owner = ARGV[1], ARGV[2], ARGV[3]
local operation, event, fingerprint = ARGV[4], ARGV[5], ARGV[6]
local body = cjson.decode(ARGV[7])
local admitted = redis.call('HGET', KEYS[1], key)
local admitted_at = redis.call('HGET', KEYS[2], key)
local progress_raw = redis.call('HGET', KEYS[3], key)
local terminal_raw = redis.call('HGET', KEYS[4], key)
local prior_event = redis.call('HGET', KEYS[5], event)
redis.call('HLEN', KEYS[6]) -- validate the discrepancy hash before any writes

local function conflict(reason)
  redis.call('HSETNX', KEYS[6], event .. '|' .. reason .. '|' .. fingerprint, cjson.encode({
    tenant_id = body.tenant_id, attempt_key = key, cause = reason
  }))
  return {'conflict', ''}
end

if admitted ~= request then return {'binding', ''} end
if operation == 'terminal' and terminal_raw then
  local recorded = cjson.decode(terminal_raw)
  if recorded.event_fingerprint == fingerprint then return {'replayed', terminal_raw} end
  return conflict('terminal_payload_conflict')
end
if prior_event then
  if prior_event ~= fingerprint then return conflict('event_payload_conflict') end
  return {'replayed', terminal_raw or ''}
end
if terminal_raw then return conflict('terminal_already_written') end
local state = progress_raw and cjson.decode(progress_raw) or nil
if state and state.owner_epoch ~= owner then return conflict('owner_epoch_conflict') end

local result = ''
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
  local point = state and state.checkpoint or nil
  local runtime = point and point.runtime or nil
  local estimate = point and point.estimate or nil
  local mismatch = runtime and estimate and
    (runtime.prompt ~= estimate.prompt or runtime.completion ~= estimate.completion)
  if mismatch then
    redis.call('HSETNX', KEYS[6], event .. '|usage_estimate_mismatch', cjson.encode({
      tenant_id = body.tenant_id, attempt_key = key, cause = 'usage_estimate_mismatch'
    }))
  end
  local function token(field)
    if not state then return {classification = 'exact', tokens = 0, source = 'no_dispatch'} end
    if not runtime then return {classification = 'unknown', source = 'unavailable'} end
    local exact = body.outcome == 'completed' and not mismatch
    return {
      classification = exact and 'exact' or 'observed_partial',
      tokens = runtime[field], source = 'runtime_usage'
    }
  end
  local row = {
    tenant_id = body.tenant_id, reservation_id = body.reservation_id, request_id = request,
    owner_epoch = owner, admitted_unix_ms = tonumber(admitted_at),
    pins = state and state.pins or body.pins, dispatch_intent = state ~= nil,
    stream_committed = body.stream_committed == true, outcome = body.outcome,
    version = 1, checkpoint = point, prompt = token('prompt'), completion = token('completion'),
    event_fingerprint = fingerprint
  }
  result = cjson.encode(row)
  redis.call('HSET', KEYS[4], key, result)
  return {'written', result}
else
  return {'binding', ''}
end
redis.call('HSET', KEYS[5], event, fingerprint)
return {'written', result}
