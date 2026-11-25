local mode = ARGV[1]
local limit = tonumber(ARGV[2])
local now = store_time_ms()
local cutoff = now - correction_window_ms

-- The active ledger's reconciliation limit also bounds this atomic read.
if redis.call('HLEN', KEYS[5]) > 10000 or redis.call('HLEN', KEYS[6]) > 10000 then
  return redis.error_reply('metering archive exceeds reconciliation limit')
end
redis.call('ZCARD', KEYS[8])
redis.call('HLEN', KEYS[9])

local function compare_keys(a, b) return a[1] < b[1] end
local function array_json(values)
  if #values == 0 then return '[]' end
  return cjson.encode(values)
end

-- Collect records and journal entries for this batch. Pair each attempt with
-- its exact journal fields to catch a stale or incomplete export on retirement.
local function snapshot(members, previously_retired, allow_empty)
  local records, events, discrepancies = {}, {}, {}
  local selected = {}
  for _, key in ipairs(members) do
    local deadline = redis.call('ZSCORE', KEYS[7], key)
    local request = redis.call('HGET', KEYS[1], key)
    local row = redis.call('HGET', KEYS[4], key)
    if not deadline or tonumber(deadline) >= cutoff or not request or not row then return nil end
    local value = cjson.decode(row)
    if value.tenant_id .. ':' .. value.reservation_id ~= key or value.request_id ~= request then return nil end
    selected[key] = true
    table.insert(records, {key, request, redis.call('HGET', KEYS[2], key) or '',
      deadline, redis.call('HGET', KEYS[3], key) or '', row})
  end
  local log = redis.call('HGETALL', KEYS[5])
  for i = 1, #log, 2 do
    local key = string.match(log[i], '^([^|]+)|')
    if selected[key] then table.insert(events, {log[i], log[i + 1]}) end
  end
  log = redis.call('HGETALL', KEYS[6])
  for i = 1, #log, 2 do
    local key = string.match(log[i], '^([^|]+)|')
    if selected[key] or previously_retired[log[i]] then
      table.insert(discrepancies, {log[i], log[i + 1]})
    end
  end
  if not allow_empty and #records + #discrepancies == 0 then return nil end
  table.sort(events, compare_keys)
  table.sort(discrepancies, compare_keys)
  return '[' .. array_json(records) .. ',' .. array_json(events) .. ',' .. array_json(discrepancies) .. ']'
end

if mode == 'export' then
  local oldest = redis.call('ZRANGEBYSCORE', KEYS[7], '-inf', '(' .. cutoff, 'LIMIT', 0, limit)
  local members = {}
  for _, key in ipairs(oldest) do
    if redis.call('HEXISTS', KEYS[4], key) == 1 then table.insert(members, key) end
  end
  -- An exception arriving after retirement still has an archive path.
  local disputes = redis.call('HKEYS', KEYS[6])
  table.sort(disputes)
  local archived, count = {}, 0
  for _, id in ipairs(disputes) do
    local key = string.match(id, '^([^|]+)|')
    if key and redis.call('HEXISTS', KEYS[9], key) == 1 and redis.call('HEXISTS', KEYS[1], key) == 0 then
      archived[id] = true
      count = count + 1
      if count >= limit then break end
    end
  end
  local candidate = snapshot(members, archived, true)
  return candidate and {'exported', candidate} or {'conflict', ''}
elseif mode == 'retire' then
  local raw = ARGV[3]
  local parts = cjson.decode(raw)
  local members, archived = {}, {}
  for _, row in ipairs(parts[1]) do table.insert(members, row[1]) end
  if #members > limit then return {'conflict', ''} end
  for _, item in ipairs(parts[3]) do
    local key = string.match(item[1], '^([^|]+)|')
    if key and redis.call('HEXISTS', KEYS[9], key) == 1 and redis.call('HEXISTS', KEYS[1], key) == 0 then
      archived[item[1]] = true
    end
  end
  if snapshot(members, archived, false) ~= raw then return {'conflict', ''} end
  -- Tombstones outlive the normal lease and release tombstone. Write them
  -- before dropping the obligation, so a partial failure cannot reopen it.
  for _, row in ipairs(parts[1]) do redis.call('HSETNX', KEYS[9], row[1], row[2]) end
  for _, row in ipairs(parts[1]) do
    for index = 1, 4 do redis.call('HDEL', KEYS[index], row[1]) end
    redis.call('ZREM', KEYS[7], row[1])
    redis.call('ZREM', KEYS[8], row[1])
  end
  for _, pair in ipairs(parts[2]) do redis.call('HDEL', KEYS[5], pair[1]) end
  for _, pair in ipairs(parts[3]) do redis.call('HDEL', KEYS[6], pair[1]) end
  return {'retired', tostring(#members)}
end
return {'conflict', ''}
