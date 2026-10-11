-- Snort 3 minimal configuration for XAI-IDPS
-- This file must be customized to match your local Snort installation paths.
-- Documentation: https://snort.org/documents

-- Set the network variables for the lab environment
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Alert output: JSON alerts to the log directory (-l flag)
-- The Python runner uses -A json to get structured output
alert_json =
{
    file = true,
    limit = 100,  -- MB
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule priority b64_data',
}

-- Include local custom rules
-- Rules directory is passed via --rule-path at runtime
include = 'snort_defaults.lua'

-- Minimal IPS configuration (detection only — no inline blocking)
ips =
{
    enable_builtin_rules = true,
    mode = 'tap',  -- passive mode; never inline/blocking
    rules = [[
        include $RULE_PATH/local.rules
    ]],
}

-- Packet processing limits (safety)
search_engine = { max_pattern_len = 20000 }
