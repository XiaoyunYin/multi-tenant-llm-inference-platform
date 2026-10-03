local reservation_state = redis.call('GET', KEYS[1])
if reservation_state == 'released' then
  return {'released', 0, 0}
end

local global_config = tostring(ARGV[6]) .. '|' .. tostring(ARGV[7]) .. '|' .. tostring(ARGV[8])
local tenant_config = tostring(ARGV[3]) .. '|' .. tostring(ARGV[4]) .. '|' .. tostring(ARGV[5])
redis.call('SETNX', KEYS[5], global_config)
redis.call('SETNX', KEYS[6], tenant_config)
redis.call('PEXPIRE', KEYS[5], ARGV[9])
redis.call('PEXPIRE', KEYS[6], ARGV[9])
if redis.call('GET', KEYS[5]) ~= global_config or redis.call('GET', KEYS[6]) ~= tenant_config then
  return {'config_mismatch', 0, 0}
end

redis.call('PEXPIRE', KEYS[5], ARGV[9])
redis.call('PEXPIRE', KEYS[6], ARGV[9])
redis.call('PEXPIRE', KEYS[2], ARGV[9])
redis.call('PEXPIRE', KEYS[3], ARGV[9])

local server_time = redis.call('TIME')
local now_ms = tonumber(server_time[1]) * 1000 + math.floor(tonumber(server_time[2]) / 1000)
local expires_ms = now_ms + tonumber(ARGV[7])

if reservation_state == 'active' then
  redis.call('ZADD', KEYS[2], expires_ms, ARGV[1])
  redis.call('ZADD', KEYS[3], expires_ms, ARGV[2])
  redis.call('PEXPIRE', KEYS[2], ARGV[9])
  redis.call('PEXPIRE', KEYS[3], ARGV[9])
  redis.call('PEXPIRE', KEYS[1], ARGV[7])
  return {'allowed', 0, 1}
end

if reservation_state then
  return redis.error_reply('invalid reservation state')
end

redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now_ms)

local rate_count = tonumber(redis.call('GET', KEYS[4]) or '0')
local rate_ttl = redis.call('PTTL', KEYS[4])
-- Zero is a valid last millisecond of a live key. Only negative TTL states
-- indicate a positive counter without a valid expiry.
if rate_count > 0 and rate_ttl < 0 then
  return redis.error_reply('invalid rate state')
end
if rate_count >= tonumber(ARGV[3]) then
  return {'tenant_rate_limit', rate_ttl, 0}
end

if redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then
  local first = redis.call('ZRANGE', KEYS[2], 0, 0, 'WITHSCORES')
  local retry_ms = 1
  if first[2] then retry_ms = math.max(1, tonumber(first[2]) - now_ms) end
  return {'tenant_concurrency_limit', retry_ms, 0}
end

if redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[6]) then
  local first = redis.call('ZRANGE', KEYS[3], 0, 0, 'WITHSCORES')
  local retry_ms = 1
  if first[2] then retry_ms = math.max(1, tonumber(first[2]) - now_ms) end
  return {'system_capacity', retry_ms, 0}
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
return {'allowed', 0, 0}
