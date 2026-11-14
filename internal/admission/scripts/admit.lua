-- Reports, expiry, retained lows and restoration are reconciled in this same
-- atomic path. No caller timestamp is accepted. Equality is expired.
local server_time = redis.call('TIME')
local now_ms = tonumber(server_time[1]) * 1000 + math.floor(tonumber(server_time[2]) / 1000)
local dynamic = ARGV[10] == 'dynamic'
local capacity = tonumber(ARGV[6])
local fresh = true
local function capture(event, code, idempotent)
  if ARGV[18] ~= 'capture' then return end
  local sequence = redis.call('INCR', KEYS[3] .. ':capture:sequence')
  redis.call('XADD', KEYS[3] .. ':capture', '*', 'capture_seq', sequence,
    'event', event, 'redis_time_ms', now_ms, 'reservation_id', ARGV[1],
    'gateway_uid', ARGV[16] or '', 'decision', code, 'idempotent', idempotent,
    'effective_b', capacity, 'effective_n', redis.call('HGET', KEYS[9], 'n') or '',
    'occupied', redis.call('ZCARD', KEYS[3]),
    'report', (ARGV[16] and redis.call('HGET', KEYS[7], ARGV[16])) or '')
end
local global_config = tostring(ARGV[6]) .. '|' .. tostring(ARGV[7]) .. '|' .. tostring(ARGV[8])
if dynamic then
  global_config = 'dynamic|' .. table.concat(ARGV, '|', 11, 14) .. '|' .. ARGV[7] .. '|' .. ARGV[8]
end
if ARGV[18] == 'capture' then global_config = global_config .. '|capture' end
redis.call('SETNX', KEYS[5], global_config)
if redis.call('GET', KEYS[5]) ~= global_config then return {'config_mismatch', 0, 0} end
if dynamic then
  -- Dynamic config/state are durable: idle time must not forget a low or allow
  -- a differently configured gateway into the same namespace.
  redis.call('PERSIST', KEYS[5])
  local hold = tonumber(ARGV[14])
  local ttl = tonumber(ARGV[13])
  local unit = tonumber(ARGV[11]) + tonumber(ARGV[12])
  local function reconcile()
    redis.call('ZREMRANGEBYSCORE', KEYS[8], '-inf', now_ms)
    local low = nil
    for _, row in ipairs(redis.call('ZRANGE', KEYS[8], 0, -1)) do
      local n = tonumber(string.match(row, '|(%d+)$'))
      if low == nil or n < low then low = n end
    end
    local minimum, maximum, deadline = nil, nil, nil
    local unknowns = {}
    local rows = redis.call('HGETALL', KEYS[7])
    for i = 1, #rows, 2 do
      local report = cjson.decode(rows[i+1])
      if now_ms >= report.expires + hold then
        redis.call('HDEL', KEYS[7], rows[i])
      else
        if report.unknown then table.insert(unknowns, report) end
        if now_ms < report.expires then
          minimum = math.min(minimum or report.n, report.n)
          maximum = math.max(maximum or report.n, report.n)
          deadline = math.min(deadline or report.expires, report.expires)
        end
      end
    end
    local effective = tonumber(redis.call('HGET', KEYS[9], 'n') or '0')
    fresh = minimum ~= nil
    if not fresh then
      redis.call('HDEL', KEYS[9], 'candidate', 'since', 'until')
      -- Refusal does not revoke reservations or erase the retained bound.
      capacity = effective * unit
      return
    end
    local bound = math.min(minimum, low or minimum)
    if bound < effective then effective = bound end
    local blocked = false
    for _, report in ipairs(unknowns) do
      -- DEC-071: after freshness, only a lower retained report can interrupt.
      if now_ms < report.expires or (report.n < minimum and now_ms < report.expires + hold) then blocked = true end
    end
    if minimum > effective and minimum == maximum and bound == minimum and not blocked then
      local candidate = tonumber(redis.call('HGET', KEYS[9], 'candidate') or '-1')
      local until_ms = tonumber(redis.call('HGET', KEYS[9], 'until') or '0')
      local since = tonumber(redis.call('HGET', KEYS[9], 'since') or tostring(now_ms))
      if candidate ~= minimum or now_ms >= until_ms then since = now_ms end
      if now_ms - since >= hold then
        effective = minimum
        redis.call('HDEL', KEYS[9], 'candidate', 'since', 'until')
      else
        redis.call('HSET', KEYS[9], 'candidate', minimum, 'since', since, 'until', deadline)
      end
    else
      redis.call('HDEL', KEYS[9], 'candidate', 'since', 'until')
    end
    redis.call('HSET', KEYS[9], 'n', effective)
    capacity = effective * unit
  end
  -- Reconcile BEFORE renewing, to detect a freshness gap between calls.
  reconcile()
  if ARGV[15] == 'report' then
    local n = tonumber(ARGV[17])
    redis.call('SET', KEYS[10], n, 'PX', ttl)
    redis.call('HSET', KEYS[7], ARGV[16], cjson.encode({n=n, expires=now_ms+ttl, unknown=false}))
    -- One bounded entry per gateway/count, preserving older lower observations
    -- even if a newer report rises before its predecessor's TTL expires.
    redis.call('ZADD', KEYS[8], now_ms+ttl+hold, ARGV[16] .. '|' .. tostring(n))
    reconcile()
    capture('report_store', 'allowed', 0)
    return {'allowed', 0, 0, capacity}
  elseif ARGV[15] == 'unknown' then
    local old = redis.call('HGET', KEYS[7], ARGV[16])
    if old then
      local report = cjson.decode(old)
      report.unknown = true
      redis.call('HSET', KEYS[7], ARGV[16], cjson.encode(report))
    end
    reconcile()
    capture('unknown', 'allowed', 0)
    return {'allowed', 0, 0, capacity}
  end
end

local function result(code, retry, idempotent)
  capture('admit', code, idempotent)
  return {code, retry, idempotent, capacity}
end
local reservation_state = redis.call('GET', KEYS[1])
if reservation_state == 'released' then
  return {'released', 0, 0}
end

local tenant_config = tostring(ARGV[3]) .. '|' .. tostring(ARGV[4]) .. '|' .. tostring(ARGV[5])
redis.call('SETNX', KEYS[5], global_config)
redis.call('SETNX', KEYS[6], tenant_config)
if not dynamic then redis.call('PEXPIRE', KEYS[5], ARGV[9]) end
redis.call('PEXPIRE', KEYS[6], ARGV[9])
if redis.call('GET', KEYS[5]) ~= global_config or redis.call('GET', KEYS[6]) ~= tenant_config then
  return {'config_mismatch', 0, 0}
end

if not dynamic then redis.call('PEXPIRE', KEYS[5], ARGV[9]) end
redis.call('PEXPIRE', KEYS[6], ARGV[9])
redis.call('PEXPIRE', KEYS[2], ARGV[9])
redis.call('PEXPIRE', KEYS[3], ARGV[9])

local expires_ms = now_ms + tonumber(ARGV[7])

if reservation_state == 'active' then
  redis.call('ZADD', KEYS[2], expires_ms, ARGV[1])
  redis.call('ZADD', KEYS[3], expires_ms, ARGV[2])
  redis.call('PEXPIRE', KEYS[2], ARGV[9])
  redis.call('PEXPIRE', KEYS[3], ARGV[9])
  redis.call('PEXPIRE', KEYS[1], ARGV[7])
  return result('allowed', 0, 1)
end

if reservation_state then
  return redis.error_reply('invalid reservation state')
end

redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now_ms)
if not fresh then return result('capacity_reports_expired', 0, 0) end

local rate_count = tonumber(redis.call('GET', KEYS[4]) or '0')
local rate_ttl = redis.call('PTTL', KEYS[4])
-- Zero is a valid last millisecond of a live key. Only negative TTL states
-- indicate a positive counter without a valid expiry.
if rate_count > 0 and rate_ttl < 0 then
  return redis.error_reply('invalid rate state')
end
if rate_count >= tonumber(ARGV[3]) then
  return result('tenant_rate_limit', rate_ttl, 0)
end

if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then
  local first = redis.call('ZRANGE', KEYS[2], 0, 0, 'WITHSCORES')
  local retry_ms = 1
  if first[2] then retry_ms = math.max(1, tonumber(first[2]) - now_ms) end
  return result('tenant_concurrency_limit', retry_ms, 0)
end

if redis.call('ZCARD', KEYS[3]) >= capacity then
  local first = redis.call('ZRANGE', KEYS[3], 0, 0, 'WITHSCORES')
  local retry_ms = 1
  if first[2] then retry_ms = math.max(1, tonumber(first[2]) - now_ms) end
  return result('system_capacity', retry_ms, 0)
end

local new_rate_count = redis.call('INCR', KEYS[4])
if new_rate_count == 1 then
  redis.call('PEXPIRE', KEYS[4], ARGV[4])
end
redis.call('SET', KEYS[1], 'active', 'PX', ARGV[7])
redis.call('ZADD', KEYS[2], expires_ms, ARGV[1])
redis.call('ZADD', KEYS[3], expires_ms, ARGV[2])
redis.call('PEXPIRE', KEYS[2], ARGV[9])
redis.call('PEXPIRE', KEYS[3], ARGV[9])
return result('allowed', 0, 0)
