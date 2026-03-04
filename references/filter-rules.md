# Filter Rules Reference

Full reference for Sigma filter rules per the v2.1.0 specification. Filters inject `AND NOT` exclusion conditions into referenced detection rules, enabling centralized tuning without modifying original rule files.

## Structure

```yaml
title: <what is being filtered out>
description: <optional explanation>
author: <name>
logsource:
    category: <should match target rule>
    product: <should match target rule>
filter:
    rules:
        - <target-rule-id>
    selection:
        <FieldName|modifier>: <value>
    condition: selection
```

### Required Fields

All three of `rules`, `selection` (at least one named detection), and `condition` must be inside the `filter` section.

| Field | Required | Notes |
|-------|----------|-------|
| `filter` | Yes | The filter section (must be a mapping) |
| `filter.rules` | Yes | List of target rule IDs |
| `filter.selection` | Yes | At least one named detection identifier |
| `filter.condition` | Yes | Condition expression referencing the detections |
| `logsource` | Recommended | Should match target rules for proper scoping |
| `title` | Yes | Describes what is being filtered |

### Fields That Should NOT Be Present

| Field | Why |
|-------|-----|
| `level` | Filters don't have their own severity |
| `status` | Filters don't have lifecycle status |

## Global vs Targeted Filters

### Targeted Filter

References specific rule IDs. The filter only applies to those rules:

```yaml
title: Exclude Admin Users from Brute Force Detection
logsource:
    category: authentication
    product: windows
filter:
    rules:
        - d4c9a825-fdb3-472e-9b0e-fa4709aba44c
    selection:
        User|startswith: 'adm_'
    condition: selection
```

### Global Filter

An empty `rules` list applies the filter to **all** rules with a matching logsource:

```yaml
title: Exclude Test Environment Events
logsource:
    product: windows
filter:
    rules: []
    selection:
        Environment: test
    condition: selection
```

## Multiple Filters on the Same Rule

Multiple filters can reference the same detection rule. Each filter operates independently -- detection identifier names (like `selection`) in different filters do not collide.

```yaml
title: Rule A
id: rule-a
logsource:
    product: windows
detection:
    sel:
        EventID: 1
    condition: sel
---
title: Filter Out Test Environment
filter:
    rules:
        - rule-a
    selection:
        Environment: test
    condition: selection
---
title: Filter Out Service Accounts
filter:
    rules:
        - rule-a
    selection:
        User|startswith: 'svc_'
    condition: selection
```

Both filters use `selection` as their detection name without conflict. The resulting logic for `rule-a` becomes:

```
sel AND NOT (test-env-filter.selection) AND NOT (svc-filter.selection)
```

## Complex Filter Conditions

Filter detections support the same syntax as regular detection blocks -- multiple identifiers and boolean conditions:

```yaml
title: Exclude Known Good Processes on DC
logsource:
    category: process_creation
    product: windows
filter:
    rules:
        - <target-rule-id>
    svchost:
        Image|endswith: '\svchost.exe'
        ParentImage|endswith: '\services.exe'
    lsass:
        Image|endswith: '\lsass.exe'
        ParentImage|endswith: '\wininit.exe'
    dc_env:
        ComputerName|startswith: 'DC-'
    condition: (svchost or lsass) and dc_env
```

## Combined: Global + Targeted

When both global and targeted filters exist, all applicable filters are applied. The order of filter application does not affect the result (they are all AND NOT):

```yaml
title: Base Rule
id: base-rule
logsource:
    product: windows
detection:
    sel:
        EventID: 1
    condition: sel
---
title: Global Filter -- Test Env
filter:
    rules: []
    env_match:
        Environment: test
    condition: env_match
---
title: Targeted Filter -- Svc Account
filter:
    rules:
        - base-rule
    svc_match:
        User: svc_account
    condition: svc_match
```

Result for `base-rule`: `sel AND NOT env_match AND NOT svc_match`
