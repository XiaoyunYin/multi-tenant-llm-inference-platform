local operation = ARGV[1]
local limit = tonumber(ARGV[2])
local now = store_time_ms()
if operation == 'migrate' then
  -- An older pre-sweep deployment must be stopped before reconciliation.
  -- Check the ceiling before reading and never infer a historical deadline
  -- for slice-1 obligations that lack an admission timestamp.
  if redis.call('HLEN', KEYS[1]) > limit then
    return redis.error_reply('metering migration exceeds cohort limit')
  end
  redis.call('ZCARD', KEYS[7])
  redis.call('ZCARD', KEYS[8])
  redis.call('HLEN', KEYS[4])
  local rows = redis.call('HKEYS', KEYS[1])
  local migrated = 0
  for _, key in ipairs(rows) do
    if not redis.call('ZSCORE', KEYS[7], key) then
      local at = tonumber(redis.call('HGET', KEYS[2], key))
      local lease = tonumber(ARGV[3])
      local deadline = at and at + lease or 0
      redis.call('ZADD', KEYS[7], deadline, key)
      if redis.call('HEXISTS', KEYS[4], key) == 0 then
        redis.call('ZADD', KEYS[8], deadline > 0 and deadline or now + lease, key)
      end
      migrated = migrated + 1
    end
  end
  return migrated
end

if operation ~= 'sweep' then return redis.error_reply('unknown metering maintenance operation') end
local expired = redis.call('ZRANGEBYSCORE', KEYS[8], '-inf', now - recovery_grace_ms, 'LIMIT', 0, limit)
redis.call('HLEN', KEYS[4])
redis.call('HLEN', KEYS[6])
local finalized = 0
for _, key in ipairs(expired) do
  local request = redis.call('HGET', KEYS[1], key)
  if request and redis.call('HEXISTS', KEYS[4], key) == 0 then
    local progress = redis.call('HGET', KEYS[3], key)
    local state = progress and cjson.decode(progress) or nil
    local owner = state and state.owner_epoch or 'owner_00000000000000000000000000000000'
    local row = terminal_row(key, request, owner, state,
      {model = '', engine = '', model_pin = '', tokenizer = ''}, 'owner_lost', false, key .. '|owner_lost')
    if state then
      state.fenced = true
      redis.call('HSET', KEYS[3], key, cjson.encode(state))
    end
    redis.call('HSET', KEYS[4], key, cjson.encode(row))
    finalized = finalized + 1
  end
  redis.call('ZREM', KEYS[8], key)
end
return finalized
