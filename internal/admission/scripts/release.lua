local reservation_state = redis.call('GET', KEYS[1])
if reservation_state == 'active' then
  redis.call('ZREM', KEYS[2], ARGV[1])
  redis.call('ZREM', KEYS[3], ARGV[2])
elseif reservation_state and reservation_state ~= 'released' then
  return redis.error_reply('invalid reservation state')
end

redis.call('SET', KEYS[1], 'released', 'PX', ARGV[3])
if ARGV[4] == 'capture' then
  local t = redis.call('TIME')
  local sequence = redis.call('INCR', KEYS[3] .. ':capture:sequence')
  redis.call('XADD', KEYS[3] .. ':capture', '*', 'capture_seq', sequence, 'event', 'release',
    'redis_time_ms', tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000),
    'reservation_id', ARGV[1], 'decision', 'released',
    'idempotent', reservation_state == 'active' and 0 or 1,
    'occupied', redis.call('ZCARD', KEYS[3]))
end
if reservation_state == 'active' then return 1 end
return 0
