local Redis = require "db.redis"
local cjson = require "cjson"

local SyncsController = {
    user_key = "user:%s:key",
    doc_key = "user:%s:document:%s",
    -- Everything below lives under the "user:<name>:" prefix, which is what
    -- delete_user sweeps, so account deletion removes history too.
    history_key = "user:%s:history:%s",
    docs_key = "user:%s:documents",
    indexed_key = "user:%s:documents_indexed",
    progress_field = "progress",
    percentage_field = "percentage",
    device_field = "device",
    device_id_field = "device_id",
    timestamp_field = "timestamp",

    error_no_redis = 1000,
    error_internal = 2000,
    error_unauthorized_user = 2001,
    error_user_exists = 2002,
    error_invalid_fields = 2003,
    -- Do we really need to handle 'document' field specifically?
    error_document_field_missing = 2004,
    error_user_registration_disabled = 2005,
    error_account_not_found = 2006,
    error_document_not_servable = 2007,
}

local null = ngx.null

-- Authenticate and delete in one operation. Distinguish an absent account from
-- a wrong key so callers can reconcile retries without retaining tombstones.
local delete_user_script = [[
local current_key = redis.call("GET", KEYS[1])
if current_key and current_key ~= ARGV[2] then
    return 0
end
local cursor = "0"
local prefix = ARGV[1]
local keys = {}
repeat
    local result = redis.call("SCAN", cursor, "COUNT", 100)
    cursor = result[1]
    for _, key in ipairs(result[2]) do
        if string.sub(key, 1, string.len(prefix)) == prefix then
            table.insert(keys, key)
        end
    end
until cursor == "0"

for _, key in ipairs(keys) do
    redis.call("DEL", key)
end
if not current_key then
    return 2
end
return 1
]]

-- Check authentication at the write itself: a request that authorized before
-- deletion must not recreate a document afterward. The history entry and the
-- document index are written in the same step so they never disagree with the
-- latest-state hash.
-- KEYS: user key, document hash, history zset, document index set
-- ARGV: auth key, timestamp, history member, document id, hash fields...
local update_progress_script = [[
if redis.call("GET", KEYS[1]) ~= ARGV[1] then
    return 0
end
redis.call("HSET", KEYS[2], unpack(ARGV, 5))
redis.call("ZADD", KEYS[3], ARGV[2], ARGV[3])
redis.call("SADD", KEYS[4], ARGV[4])
return 1
]]

-- Documents written before history existed have a hash but no index entry.
-- Index them once per account, guarded by a flag so the keyspace scan does not
-- run on every listing.
-- KEYS: index set, flag. ARGV: document key prefix
local index_documents_script = [[
if redis.call("EXISTS", KEYS[2]) == 1 then
    return 0
end
local cursor = "0"
local prefix = ARGV[1]
local plen = string.len(prefix)
repeat
    local result = redis.call("SCAN", cursor, "COUNT", 100)
    cursor = result[1]
    for _, key in ipairs(result[2]) do
        if string.sub(key, 1, plen) == prefix then
            redis.call("SADD", KEYS[1], string.sub(key, plen + 1))
        end
    end
until cursor == "0"
redis.call("SET", KEYS[2], "1")
return 1
]]

-- Authenticate and update in one operation so concurrent changes using the
-- same current key cannot both succeed. Document keys are never touched.
local update_password_script = [[
if redis.call("GET", KEYS[1]) ~= ARGV[1] then
    return 0
end
redis.call("SET", KEYS[1], ARGV[2])
return 1
]]

local day_seconds = 86400
local max_stats_days = 366
local default_history_limit = 100
local max_history_limit = 1000

-- Query-string integer, or nil when absent or malformed.
local function int_param(value)
    local n = tonumber(value)
    if n and n == math.floor(n) then
        return n
    end
end

local function decode_entry(member)
    local ok, e = pcall(cjson.decode, member)
    if not ok or type(e) ~= "table" then
        return nil
    end
    return {
        timestamp = e.t,
        percentage = e.p,
        progress = e.g,
        device = e.d,
        device_id = e.i,
    }
end

-- A hash field read back from redis; absent fields come back as ngx.null.
local function field(value, convert)
    if value == nil or value == null then
        return nil
    end
    return convert and convert(value) or value
end

-- Whether a field is valid, i.e. not an empty string.
local function is_valid_field(field)
    return type(field) == "string" and string.len(field) > 0
end

-- Whether a field is valid as a redis key, i.e. not an empty string and contains no colon.
local function is_valid_key_field(field)
    return is_valid_field(field) and not string.find(field, ":")
end

-- The read route binds :document against a fixed character class (see
-- gin/core/routes.lua, build_named_parameters), so an id outside it is stored
-- by PUT and then 404s at nginx before the controller is reached. Refuse it on
-- the way in rather than accepting a write that can never be read back.
local function is_servable_document(field)
    return string.match(field, "^[A-Za-z0-9_]+$") ~= nil
end

-- gin builds a controller per request, so the handle lives exactly as long as
-- the request does.
function SyncsController:getRedis()
    if self.redis then
        return self.redis
    end
    local redis = Redis:new()
    if not redis then
        self:raise_error(self.error_no_redis)
    else
        self.redis = redis
        return redis
    end
end

function SyncsController:authorize()
    local redis = self:getRedis()
    local auth_user = self.request.headers['x-auth-user']
    local auth_key = self.request.headers['x-auth-key']
    if is_valid_field(auth_key) and is_valid_key_field(auth_user) then
        local key, err = redis:get(string.format(self.user_key, auth_user))
        if auth_key == key then
            return auth_user
        end
    end
end

function SyncsController:auth_user()
    if self:authorize() then
        return 200, { authorized = "OK" }
    else
        self:raise_error(self.error_unauthorized_user)
    end
end

function SyncsController:create_user()
    local redis = self:getRedis()

    if not is_valid_key_field(self.request.body.username)
    or not is_valid_field(self.request.body.password) then
        self:raise_error(self.error_invalid_fields)
    end

    local created, err = redis:setnx(string.format(self.user_key, self.request.body.username),
        self.request.body.password)
    if created == 0 then
        self:raise_error(self.error_user_exists)
    elseif created ~= 1 then
        self:raise_error(self.error_internal)
    end
    return 201, { username = self.request.body.username }
end

function SyncsController:create_user_disabled()
    self:raise_error(self.error_user_registration_disabled)
end

function SyncsController:delete_user()
    local username = self.request.headers['x-auth-user']
    local current_key = self.request.headers['x-auth-key']
    if not is_valid_key_field(username) or not is_valid_field(current_key) then
        self:raise_error(self.error_unauthorized_user)
    end

    local redis = self:getRedis()
    local deleted, err = redis:eval(delete_user_script, 1,
        string.format(self.user_key, username), "user:" .. username .. ":", current_key)
    if deleted == 0 then
        self:raise_error(self.error_unauthorized_user)
    elseif deleted == 2 then
        self:raise_error(self.error_account_not_found)
    elseif deleted ~= 1 then
        self:raise_error(self.error_internal)
    end

    return 200, { deleted = true }
end

function SyncsController:update_password()
    local username = self.request.headers['x-auth-user']
    local current_key = self.request.headers['x-auth-key']
    if not is_valid_key_field(username) or not is_valid_field(current_key) then
        self:raise_error(self.error_unauthorized_user)
    end

    local body = self.request.body
    if type(body) ~= "table" or not is_valid_field(body.password) then
        self:raise_error(self.error_invalid_fields)
    end

    local redis = self:getRedis()
    local updated, err = redis:eval(update_password_script, 1,
        string.format(self.user_key, username), current_key, body.password)
    if updated == 0 then
        self:raise_error(self.error_unauthorized_user)
    elseif updated ~= 1 then
        self:raise_error(self.error_internal)
    end

    return 200, { updated = true }
end

function SyncsController:get_progress()
    local redis = self:getRedis()

    local username = self:authorize()
    if not username then
        self:raise_error(self.error_unauthorized_user)
    end

    local doc = self.params.document
    if not is_valid_key_field(doc) then
        self:raise_error(self.error_document_field_missing)
    end

    local key = string.format(self.doc_key, username, doc)
    local res = {}
    local results, err = redis:hmget(key,
                                     self.percentage_field,
                                     self.progress_field,
                                     self.device_field,
                                     self.device_id_field,
                                     self.timestamp_field)
    if err then
        self:raise_error(self.error_internal)
    end

    if results[1] and results[1] ~= null then
        res.percentage = tonumber(results[1])
    end
    if results[2] and results[2] ~= null then
        res.progress = results[2]
    end
    if results[3] and results[3] ~= null then
        res.device = results[3]
    end
    if results[4] and results[4] ~= null then
        res.device_id = results[4]
    end
    if results[5] and results[5] ~= null then
        res.timestamp = tonumber(results[5])
    end

    if next(res) then
        -- We do not want to have an almost empty table with document field only.
        res.document = doc
    end

    return 200, res
end

function SyncsController:update_progress()
    local redis = self:getRedis()

    local username = self:authorize()
    if not username then
        self:raise_error(self.error_unauthorized_user)
    end

    local doc = self.request.body.document
    if not is_valid_key_field(doc) then
        self:raise_error(self.error_document_field_missing)
    end
    if not is_servable_document(doc) then
        self:raise_error(self.error_document_not_servable)
    end

    local percentage = tonumber(self.request.body.percentage)
    local progress = self.request.body.progress
    local device = self.request.body.device
    local device_id = self.request.body.device_id
    local timestamp = os.time()
    if percentage and progress and device then
        local key = string.format(self.doc_key, username, doc)
        local member = cjson.encode({
            t = timestamp,
            p = percentage,
            g = progress,
            d = device,
            i = device_id,
        })
        -- Score by millisecond time so writes within one second keep their
        -- order; equal scores would be ordered by the member's text.
        local fields = {
            self.request.headers['x-auth-key'],
            string.format("%.3f", ngx.now()),
            member,
            doc,
            self.percentage_field, percentage,
            self.progress_field, progress,
            self.device_field, device,
            self.timestamp_field, timestamp,
        }
        if device_id ~= nil then
            table.insert(fields, self.device_id_field)
            table.insert(fields, device_id)
        end
        local updated, err = redis:eval(update_progress_script, 4,
            string.format(self.user_key, username), key,
            string.format(self.history_key, username, doc),
            string.format(self.docs_key, username),
            unpack(fields))
        if updated == 0 then
            self:raise_error(self.error_unauthorized_user)
        elseif updated ~= 1 then
            self:raise_error(self.error_internal)
        end
        return 200, {
            document = doc,
            timestamp = timestamp,
        }
    else
        self:raise_error(self.error_invalid_fields)
    end
end

-- Authenticate or raise 401; returns the username.
function SyncsController:require_user()
    local username = self:authorize()
    if not username then
        self:raise_error(self.error_unauthorized_user)
    end
    return username
end

function SyncsController:list_documents()
    local username = self:require_user()
    local redis = self:getRedis()

    local _, err = redis:eval(index_documents_script, 2,
        string.format(self.docs_key, username),
        string.format(self.indexed_key, username),
        string.format(self.doc_key, username, ""))
    if err then
        self:raise_error(self.error_internal)
    end

    local ids, err = redis:smembers(string.format(self.docs_key, username))
    if err then
        self:raise_error(self.error_internal)
    end
    table.sort(ids)

    local documents = {}
    if #ids > 0 then
        redis:init_pipeline()
        for _, id in ipairs(ids) do
            redis:hmget(string.format(self.doc_key, username, id),
                self.percentage_field, self.progress_field, self.device_field,
                self.device_id_field, self.timestamp_field)
        end
        local results, err = redis:commit_pipeline()
        if not results then
            self:raise_error(self.error_internal)
        end
        for i, id in ipairs(ids) do
            local r = results[i]
            if type(r) == "table" and r[1] ~= null then
                documents[#documents + 1] = {
                    document = id,
                    percentage = field(r[1], tonumber),
                    progress = field(r[2]),
                    device = field(r[3]),
                    device_id = field(r[4]),
                    timestamp = field(r[5], tonumber),
                }
            end
        end
        -- Most recently read first.
        table.sort(documents, function(a, b)
            return (a.timestamp or 0) > (b.timestamp or 0)
        end)
    end

    return 200, { documents = documents }
end

-- Position timeline of one book, oldest first. `from` and `to` are unix
-- seconds; `limit` keeps the newest entries when the range holds more.
function SyncsController:get_history()
    local username = self:require_user()

    local doc = self.params.document
    if not is_valid_key_field(doc) then
        self:raise_error(self.error_document_field_missing)
    end

    local query = self.request.uri_params
    local from = int_param(query.from)
    local to = int_param(query.to)
    local limit = int_param(query.limit) or default_history_limit
    if limit < 1 or limit > max_history_limit then
        self:raise_error(self.error_invalid_fields)
    end

    local redis = self:getRedis()
    local members, err = redis:zrevrangebyscore(
        string.format(self.history_key, username, doc),
        to or "+inf", from or "-inf", "LIMIT", 0, limit)
    if err then
        self:raise_error(self.error_internal)
    end

    local entries = {}
    for i = #members, 1, -1 do
        local entry = decode_entry(members[i])
        if entry then
            entries[#entries + 1] = entry
        end
    end

    return 200, { document = doc, history = entries }
end

-- Per-day activity over a range. A day's `advanced` is the sum of forward
-- movement (in percentage points) between consecutive syncs of the same book;
-- the last sync before the range is the baseline, so the first sync inside it
-- is counted against real prior state. Syncs only fire when KOReader pushes, so
-- these are trends, not a reading clock. Days are UTC unless `tz_offset`
-- (minutes east of UTC) is given.
function SyncsController:get_stats()
    local username = self:require_user()

    local query = self.request.uri_params
    local now = os.time()
    local to = int_param(query.to) or now
    local from = int_param(query.from) or (to - 30 * day_seconds)
    local tz = (int_param(query.tz_offset) or 0) * 60
    if from > to or to - from > max_stats_days * day_seconds
    or math.abs(tz) > day_seconds then
        self:raise_error(self.error_invalid_fields)
    end

    local redis = self:getRedis()
    local ids, err = redis:smembers(string.format(self.docs_key, username))
    if err then
        self:raise_error(self.error_internal)
    end
    table.sort(ids)

    local days = {}
    local books = {}
    local function day_of(ts)
        local start = math.floor((ts + tz) / day_seconds) * day_seconds - tz
        local d = days[start]
        if not d then
            d = { date = os.date("!%Y-%m-%d", start + tz), syncs = 0, advanced = 0, docs = {} }
            days[start] = d
        end
        return d
    end

    for _, id in ipairs(ids) do
        local key = string.format(self.history_key, username, id)
        local prev
        local before = redis:zrevrangebyscore(key, "(" .. from, "-inf", "LIMIT", 0, 1)
        if type(before) == "table" and before[1] then
            prev = decode_entry(before[1])
        end
        local members, err = redis:zrangebyscore(key, from, to)
        if err then
            self:raise_error(self.error_internal)
        end
        local book = { document = id, syncs = 0, advanced = 0 }
        for _, member in ipairs(members) do
            local e = decode_entry(member)
            if e and e.timestamp then
                local d = day_of(e.timestamp)
                d.syncs = d.syncs + 1
                d.docs[id] = true
                book.syncs = book.syncs + 1
                book.last_timestamp = e.timestamp
                book.percentage = e.percentage
                if prev and e.percentage and prev.percentage
                and e.percentage > prev.percentage then
                    local gain = (e.percentage - prev.percentage) * 100
                    d.advanced = d.advanced + gain
                    book.advanced = book.advanced + gain
                end
                prev = e
            end
        end
        if book.syncs > 0 then
            books[#books + 1] = book
        end
    end

    local out = {}
    for start, d in pairs(days) do
        local n = 0
        for _ in pairs(d.docs) do n = n + 1 end
        out[#out + 1] = {
            date = d.date,
            syncs = d.syncs,
            books = n,
            advanced = math.floor(d.advanced * 100 + 0.5) / 100,
            start = start,
        }
    end
    table.sort(out, function(a, b) return a.start < b.start end)
    for _, d in ipairs(out) do d.start = nil end
    for _, b in ipairs(books) do
        b.advanced = math.floor(b.advanced * 100 + 0.5) / 100
    end
    table.sort(books, function(a, b) return b.last_timestamp < a.last_timestamp end)

    return 200, { from = from, to = to, days = out, books = books }
end

function SyncsController:healthcheck()
    return 200, { state = 'OK' }
end

-- gin dispatches straight to the action and turns raise_error into a response
-- with pcall, so an action has no return point every path passes through. The
-- connection goes back to the pool here, inside the content phase: nginx
-- finalizes cosockets before log_by_lua runs, where set_keepalive fails with
-- "closed".
local function releasing(action)
    return function(self, ...)
        local ok, status, body, headers = pcall(action, self, ...)
        if self.redis then
            Redis.release(self.redis)
            self.redis = nil
        end
        if not ok then
            error(status, 0)
        end
        return status, body, headers
    end
end

for _, action in ipairs({
    "auth_user",
    "create_user",
    "create_user_disabled",
    "delete_user",
    "update_password",
    "get_progress",
    "update_progress",
    "list_documents",
    "get_history",
    "get_stats",
    "healthcheck"
}) do
    SyncsController[action] = releasing(SyncsController[action])
end

return SyncsController
