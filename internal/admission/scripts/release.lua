local reservation_state = redis.call('GET', KEYS[1])
if reservation_state == 'active' then
  redis.call('ZREM', KEYS[2], ARGV[1])
  redis.call('ZREM', KEYS[3], ARGV[2])
elseif reservation_state and reservation_state ~= 'released' then
  return redis.error_reply('invalid reservation state')
end

redis.call('SET', KEYS[1], 'released', 'PX', ARGV[3])
if reservation_state == 'active' then return 1 end
return 0
