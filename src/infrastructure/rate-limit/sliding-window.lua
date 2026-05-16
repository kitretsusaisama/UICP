-- Atomic sliding window rate limiter
-- KEYS[1] = rate limit key
-- ARGV[1] = window in seconds
-- ARGV[2] = maximum requests allowed in window

local key = KEYS[1]
local window = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])

-- Get current count
local current = redis.call('GET', key)

-- If at or above limit, return -1 to indicate rejection
if current and tonumber(current) >= limit then
  return -1
end

-- Atomic increment (key is created with expiry if it doesn't exist)
local count = redis.call('INCR', key)

-- Set expiry only on first increment (atomic via single eval)
if count == 1 then
  redis.call('EXPIRE', key, window)
end

-- Return current count (caller compares to limit)
return count