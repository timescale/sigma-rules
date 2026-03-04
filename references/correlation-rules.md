# Correlation Rules Reference

Full reference for all 8 Sigma correlation rule types per the v2.1.0 specification.

## Structure

A correlation rule always requires the `correlation` section:

```yaml
title: <description>
id: <UUIDv4>
correlation:
    type: <correlation_type>
    rules:
        - <rule-id or wildcard pattern>
    group-by:
        - <field_name>
    timespan: <duration>
    condition: <threshold or expression>
    generate: <boolean>          # optional, default false
level: <level>
```

### Required Fields

| Field | Required For | Notes |
|-------|-------------|-------|
| `type` | All | One of the 8 correlation types |
| `rules` | All | List of rule IDs or wildcard patterns |
| `group-by` | All | Fields to partition events by |
| `timespan` | All | Sliding window duration |
| `condition` | Non-temporal | Threshold mapping or boolean expression |
| `condition.field` | `value_count`, `value_sum`, `value_avg`, `value_percentile`, `value_median` | Which field to aggregate |

### Timespan Units

| Unit | Suffix | Example |
|------|--------|---------|
| Seconds | `s` | `30s` |
| Minutes | `m` | `5m` |
| Hours | `h` | `1h` |
| Days | `d` | `7d` |
| Weeks | `w` | `1w` |
| Months (uppercase) | `M` | `1M` |
| Years | `y` | `1y` |

Both `timespan` and `timeframe` are accepted as key names.

### Generate Flag

When `generate: true`, the correlation rule produces an alert even when detecting rules do not individually fire. Used for metric-based correlations where the aggregate threshold is the alert trigger.

---

## Count Types

### event_count

Count matching events per group key within the time window.

```yaml
title: Brute Force Login Attempts
correlation:
    type: event_count
    rules:
        - <failed-login-rule-id>
    group-by:
        - User
        - SourceIP
    timespan: 5m
    condition:
        gte: 10
level: high
```

### value_count

Count distinct values of a specific field per group key.

```yaml
title: Login From Many Sources
correlation:
    type: value_count
    rules:
        - <login-rule-id>
    group-by:
        - User
    timespan: 10m
    condition:
        field: SourceIP
        gte: 5
level: high
```

The `field` key in the condition specifies which field's distinct values to count.

---

## Metric Types

### value_sum

Sum a numeric field across matching events per group.

```yaml
title: Large Data Exfiltration
correlation:
    type: value_sum
    rules:
        - <outbound-transfer-rule-id>
    group-by:
        - SourceIP
    timespan: 1h
    condition:
        field: BytesSent
        gte: 1073741824
level: critical
```

### value_avg

Average of a numeric field per group.

```yaml
title: Abnormal Average Request Size
correlation:
    type: value_avg
    rules:
        - <http-request-rule-id>
    group-by:
        - ClientIP
    timespan: 30m
    condition:
        field: RequestSize
        gte: 10000
level: medium
```

### value_percentile

Compute a percentile of a numeric field per group.

```yaml
title: 95th Percentile Response Time
correlation:
    type: value_percentile
    rules:
        - <response-time-rule-id>
    group-by:
        - ServiceName
    timespan: 15m
    condition:
        field: ResponseTime
        gte: 5000
level: medium
```

### value_median

Compute the median of a numeric field per group.

```yaml
title: Median Payload Size Spike
correlation:
    type: value_median
    rules:
        - <payload-rule-id>
    group-by:
        - DestinationIP
    timespan: 1h
    condition:
        field: PayloadSize
        gte: 4096
level: medium
```

---

## Temporal Types

### temporal

Require multiple detection rules to fire within the same time window for the same group. No ordering requirement.

```yaml
title: Recon Then Lateral Movement
correlation:
    type: temporal
    rules:
        - <recon-rule-id>
        - <lateral-movement-rule-id>
    group-by:
        - SourceIP
    timespan: 15m
    condition: "<recon-rule-id> and <lateral-movement-rule-id>"
level: critical
```

When no condition is specified, temporal defaults to `{gte: 1}` -- at least one match of each referenced rule.

### temporal_ordered

Same as temporal, but the rules must fire in the order they appear in the condition expression.

```yaml
title: Credential Dump Then Exfiltration
correlation:
    type: temporal_ordered
    rules:
        - <credential-dump-rule-id>
        - <exfiltration-rule-id>
    group-by:
        - User
    timespan: 30m
    condition: "<credential-dump-rule-id> and <exfiltration-rule-id>"
level: critical
```

---

## Condition Operators

For threshold-style conditions (count and metric types):

| Operator | Meaning |
|----------|---------|
| `gt` | Greater than |
| `gte` | Greater than or equal |
| `lt` | Less than |
| `lte` | Less than or equal |
| `eq` | Equal |
| `neq` | Not equal |

Multiple operators can be combined in a single condition:

```yaml
condition:
    gt: 10
    lte: 100
```

All operator values must be numeric.

---

## Multi-Document Pattern

Detection and correlation rules are commonly paired in the same file using `---` separators:

```yaml
title: Failed SSH Login
id: ssh-failed-login
logsource:
    category: authentication
    product: linux
detection:
    selection:
        EventType: ssh_failed
    condition: selection
level: low
---
title: SSH Brute Force
id: ssh-brute-force
correlation:
    type: event_count
    rules:
        - ssh-failed-login
    group-by:
        - User
        - SourceIP
    timespan: 5m
    condition:
        gte: 10
level: critical
```

Use `action: global` to share logsource when the detection and correlation share the same platform:

```yaml
action: global
logsource:
    product: windows
    category: process_creation
level: medium
---
title: Detect Cmd Execution
id: detect-cmd
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
---
action: repeat
title: Detect PowerShell Execution
id: detect-ps
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
---
title: Recon Burst
correlation:
    type: event_count
    rules:
        - detect-cmd
        - detect-ps
    group-by:
        - User
    timespan: 60s
    condition:
        gte: 3
level: high
```

## Rule References with Wildcards

The `rules` field supports wildcard patterns to match multiple rule IDs:

```yaml
correlation:
    rules:
        - "recon-*"       # matches recon-cmd, recon-ps, etc.
```
