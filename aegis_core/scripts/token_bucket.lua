-- Atomic token bucket rate limiter.
--
-- KEYS[1] = bucket key
-- ARGV[1] = capacity (max tokens the bucket can hold)
-- ARGV[2] = refill_rate (tokens added per second)
-- ARGV[3] = now (current time, seconds, float)
-- ARGV[4] = cost (tokens this request consumes)
-- ARGV[5] = ttl_seconds (expire the key after this long with no traffic)
--
-- Returns {allowed, remaining_tokens}. Runs as a single Lua script so the
-- read-refill-decrement-write sequence can't race with a concurrent request
-- against the same key.

local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill_rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local ttl_seconds = tonumber(ARGV[5])

local bucket = redis.call("HMGET", key, "tokens", "updated_at")
local tokens = tonumber(bucket[1])
local updated_at = tonumber(bucket[2])

if tokens == nil then
  tokens = capacity
  updated_at = now
end

local elapsed = math.max(0, now - updated_at)
tokens = math.min(capacity, tokens + elapsed * refill_rate)

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call("HSET", key, "tokens", tostring(tokens), "updated_at", tostring(now))
redis.call("EXPIRE", key, ttl_seconds)

return {allowed, tostring(tokens)}
