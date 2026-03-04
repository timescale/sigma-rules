---
name: sigma-rules
description: "Author Sigma detection rules, correlation rules, filter rules, and processing pipelines from natural language descriptions. Covers the full Sigma v2.1.0 specification including logsource, detection blocks, field modifiers, condition expressions, multi-document YAML, correlation types (event_count, value_count, temporal, temporal_ordered, value_sum, value_avg, value_percentile, value_median), filter injection, and pySigma-compatible pipelines. Use this skill whenever the user mentions Sigma rules, SIEM detection, detection engineering, detection-as-code, SigmaHQ, correlation rules, Sigma filters, Sigma pipelines, field modifiers, logsource, or asks to write, review, or fix detection rules -- even if they don't explicitly say 'Sigma'."
---

# Sigma Rules

Write Sigma detection, correlation, and filter rules plus processing pipelines per the [Sigma v2.1.0 specification](https://github.com/SigmaHQ/sigma-specification). This version is backward-compatible with v2.0.0.

## Detection Rules

A detection rule matches log events against field conditions.

### Template

```yaml
title: <concise description of what is detected>
id: <UUIDv4>
status: <stable|test|experimental|deprecated|unsupported>
description: <what this rule detects and why it matters>
author: <name>
date: YYYY-MM-DD
modified: YYYY-MM-DD
references:
    - <URL>
tags:
    - attack.<tactic>
    - attack.<technique_id>
logsource:
    category: <category>
    product: <product>
    service: <service>
detection:
    <selection_name>:
        <FieldName|modifier1|modifier2>: <value or list>
    <filter_name>:
        <FieldName>: <value>
    condition: <selection_name> and not <filter_name>
falsepositives:
    - <known false positive scenario>
level: <informational|low|medium|high|critical>
```

### Detection Block

The detection section maps named identifiers to field conditions, then combines them with a condition expression.

**YAML mapping** (AND-linked fields):

```yaml
selection:
    EventID: 1
    Image|endswith: '\whoami.exe'
```

**YAML list of mappings** (OR-linked):

```yaml
selection:
    - EventID: 1
      Image|endswith: '\whoami.exe'
    - EventID: 4688
      NewProcessName|endswith: '\whoami.exe'
```

**Keyword list** (field-agnostic search):

```yaml
keywords:
    - 'mimikatz'
    - 'sekurlsa'
```

### Field Modifiers

Modifiers chain with `|` on the field name. Common modifiers:

| Modifier | Effect |
|----------|--------|
| `contains` | Substring match (wraps value in `*...*`) |
| `startswith` | Prefix match (appends `*`) |
| `endswith` | Suffix match (prepends `*`) |
| `all` | AND-link all values (default is OR) |
| `re` | Value is a regex (disables wildcard parsing) |
| `cidr` | CIDR network match |
| `base64` / `base64offset` | Match base64-encoded value |
| `wide` | UTF-16LE encoding |
| `windash` | Match both `-` and `/` dash styles |
| `exists` | Field existence check (value: `true`/`false`) |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison |
| `cased` | Case-sensitive match |
| `fieldref` | Value references another field name |

For the full list of 30 modifiers, incompatible combinations, and encoding chains, see [references/modifiers.md](references/modifiers.md).

### Condition Expressions

Conditions combine named detections with boolean logic:

```yaml
condition: selection and not filter
condition: 1 of selection* or keywords
condition: all of them
```

Precedence: `not` > `and` > `or`. Quantifiers: `1 of`, `all of`, `any of`, `N of`. Wildcard patterns match detection names (`selection*`). `them` matches all identifiers except `_`-prefixed ones.

For the full grammar, see [references/condition-syntax.md](references/condition-syntax.md).

### Wildcards in Values

`*` matches any number of characters, `?` matches exactly one. Escape with backslash: `\*`, `\?`, `\\`. Non-special backslash sequences like `\W` are preserved literally (important for Windows paths).

### Worked Example

**Request:** "Detect use of the Windows command line to delete shadow copies"

```yaml
title: Shadow Copy Deletion via Vssadmin or WMIC
id: c947b146-0abc-4f7a-a55e-bf2fcb8dbb60
status: test
description: >
    Detects the use of vssadmin or wmic to delete volume shadow copies,
    a common ransomware and anti-forensics technique.
author: Security Team
date: 2025-01-15
references:
    - https://attack.mitre.org/techniques/T1490/
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection_vssadmin:
        Image|endswith: '\vssadmin.exe'
        CommandLine|contains|all:
            - 'delete'
            - 'shadows'
    selection_wmic:
        Image|endswith: '\wmic.exe'
        CommandLine|contains|all:
            - 'shadowcopy'
            - 'delete'
    condition: 1 of selection_*
falsepositives:
    - Legitimate backup rotation scripts
level: high
```

For the full detection rule reference (metadata fields, logsource, multi-document YAML, tags), see [references/detection-rules.md](references/detection-rules.md).

---

## Correlation Rules

Correlation rules aggregate or sequence events matched by detection rules over a time window, grouped by key fields.

### Template

```yaml
title: <what the correlation detects>
id: <UUIDv4>
correlation:
    type: <correlation_type>
    rules:
        - <rule-id or wildcard>
    group-by:
        - <field>
    timespan: <duration>
    condition:
        gte: <threshold>
level: <level>
```

### Correlation Types

| Type | Purpose | Condition |
|------|---------|-----------|
| `event_count` | Count matching events per group | Threshold: `{gte: N}` |
| `value_count` | Count distinct values of a field per group | Threshold with `field`: `{field: X, gte: N}` |
| `temporal` | Multiple rule types fire in same window | Extended: `"rule_a and rule_b"` or default |
| `temporal_ordered` | Same as temporal, rules must fire in order | Extended: `"rule_a and rule_b"` |
| `value_sum` | Sum a numeric field across events | Threshold with `field` |
| `value_avg` | Average a numeric field | Threshold with `field` |
| `value_percentile` | Percentile of a numeric field | Threshold with `field` |
| `value_median` | Median of a numeric field | Threshold with `field` |

### Condition Block

**Threshold (mapping):** for count/metric types:

```yaml
condition:
    gte: 100
```

With field (required for `value_count`, `value_sum`, `value_avg`, `value_percentile`, `value_median`):

```yaml
condition:
    field: SourceIP
    gte: 5
```

Operators: `gt`, `gte`, `lt`, `lte`, `eq`, `neq`. Values must be numeric.

**Extended (string):** for temporal types:

```yaml
condition: "recon_scan and lateral_movement"
```

### Timespan

Format: integer + unit suffix. Units: `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks), `M` (months, uppercase), `y` (years). Both `timespan` and `timeframe` keys are accepted.

### Worked Example

**Request:** "Alert on brute force: more than 5 failed logins from the same user within 5 minutes"

```yaml
title: Failed Login
id: d4c9a825-fdb3-472e-9b0e-fa4709aba44c
status: test
logsource:
    category: authentication
    product: windows
detection:
    selection:
        EventType: failed_login
    condition: selection
level: low
---
title: Brute Force Detection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
correlation:
    type: event_count
    rules:
        - d4c9a825-fdb3-472e-9b0e-fa4709aba44c
    group-by:
        - User
    timespan: 5m
    condition:
        gte: 5
level: critical
```

For all 8 correlation types with full examples, see [references/correlation-rules.md](references/correlation-rules.md).

---

## Filter Rules

Filter rules inject `AND NOT` exclusion conditions into referenced detection rules, enabling centralized tuning without modifying original rules.

### Template

```yaml
title: <what is being filtered>
logsource:
    category: <must match target rule>
    product: <must match target rule>
filter:
    rules:
        - <target-rule-id>
    selection:
        <FieldName|modifier>: <value>
    condition: selection
```

### Key Points

- `selection`, `condition`, and `rules` all live inside the `filter` section
- `rules: []` (empty) applies the filter globally to all matching rules
- Filter rules should **not** have `level` or `status` fields
- Multiple filters on the same rule use independent detection namespaces (no collision)

### Worked Example

**Request:** "Exclude service accounts from the brute force rule"

```yaml
title: Exclude Service Accounts from Brute Force
logsource:
    category: authentication
    product: windows
filter:
    rules:
        - d4c9a825-fdb3-472e-9b0e-fa4709aba44c
    selection:
        User|startswith: 'svc_'
    condition: selection
```

For global vs targeted filters and multi-filter patterns, see [references/filter-rules.md](references/filter-rules.md).

---

## Processing Pipelines

Pipelines transform Sigma rule ASTs before evaluation -- typically for field name mapping between generic Sigma field names and backend-specific schemas (ECS, Splunk CIM, etc.).

### Template

```yaml
name: <pipeline name>
priority: <integer, lower runs first>
transformations:
  - type: field_name_mapping
    mapping:
      <SigmaField>: <backend_field>
    rule_conditions:
      - type: logsource
        product: <product>
```

### Common Transformations

| Type | Purpose | Key Parameters |
|------|---------|----------------|
| `field_name_mapping` | Rename fields | `mapping: {old: new}` |
| `field_name_prefix` | Add prefix to all fields | `prefix: string` |
| `replace_string` | Regex replacement in values | `regex`, `replacement` |
| `drop_detection_item` | Remove matching detection items | (none) |
| `change_logsource` | Rewrite logsource fields | `category`, `product`, `service` |
| `add_condition` | Inject extra conditions | `conditions: {field: value}` |

### Rule Conditions

Transformations only apply when all `rule_conditions` match:

| Type | Matches When |
|------|-------------|
| `logsource` | Rule logsource matches `category`/`product`/`service` |
| `contains_detection_item` | Rule has a detection item with the given `field` |
| `tag` | Rule has the given tag |
| `is_sigma_rule` | Document is a detection rule |
| `is_sigma_correlation_rule` | Document is a correlation rule |

### Worked Example

**Request:** "Map generic Sigma fields to Elastic Common Schema for Windows process creation rules"

```yaml
name: ECS Windows Process Creation
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      Image: process.executable
      ParentImage: process.parent.executable
      User: user.name
      OriginalFileName: process.pe.original_file_name
      Hashes: process.hash
      ParentCommandLine: process.parent.command_line
      IntegrityLevel: winlog.event_data.IntegrityLevel
      LogonId: winlog.logon.id
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
  - type: change_logsource
    product: windows
    category: process_creation
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
```

For the full list of 26 transformations, all condition types, variables, and expression syntax, see [references/pipelines.md](references/pipelines.md).

---

## Authoring Checklist

When writing or reviewing Sigma rules, verify:

- [ ] `title` is present and under 256 characters
- [ ] `id` is a valid UUIDv4 (`8-4-4-4-12` hex format)
- [ ] `status` is one of: `stable`, `test`, `experimental`, `deprecated`, `unsupported`
- [ ] `level` is one of: `informational`, `low`, `medium`, `high`, `critical`
- [ ] `date` and `modified` use `YYYY-MM-DD` format; `modified` >= `date`
- [ ] `logsource` is present with at least one of `category`, `product`, `service`
- [ ] Logsource values are lowercase
- [ ] Detection has at least one named identifier and a `condition`
- [ ] Condition only references identifiers that exist in the detection block
- [ ] Tags match `^[a-z0-9_-]+\.[a-z0-9._-]+$` (e.g. `attack.t1059`)
- [ ] No incompatible modifier combinations (e.g. `contains|startswith`, `re|contains`)
- [ ] `deprecated` rules have a `related` entry
- [ ] Correlation rules have `type`, `rules`, `group-by`, and `timespan`
- [ ] Filter rules have `rules`, `selection`, and `condition` inside the `filter` section
- [ ] Filter rules do not have `level` or `status`

## Multi-Document YAML

Multiple rules in one file are separated by `---`. Collection actions control template inheritance:

- `action: global` -- store as template merged into all subsequent rules
- `action: reset` -- clear the template
- `action: repeat` -- clone the previous rule and merge current fields on top

This is commonly used to share `logsource` across detection + correlation rule pairs.

## Additional References

- [Detection rules deep dive](references/detection-rules.md) -- metadata, logsource, multi-document, tags
- [Correlation rules](references/correlation-rules.md) -- all 8 types with examples
- [Filter rules](references/filter-rules.md) -- global vs targeted, multi-filter patterns
- [Pipelines](references/pipelines.md) -- all 26 transformations and conditions
- [Field modifiers](references/modifiers.md) -- all 30 modifiers, chaining, compatibility
- [Condition syntax](references/condition-syntax.md) -- grammar, precedence, quantifiers
