# Detection Rules Reference

Full reference for Sigma detection rules per the v2.1.0 specification.

## Metadata Fields

| Field | Required | Format | Notes |
|-------|----------|--------|-------|
| `title` | Yes | String, max 256 chars | Concise description of what is detected |
| `id` | Recommended | UUIDv4 (`8-4-4-4-12` hex) | Stable identifier; never reuse |
| `status` | Recommended | Enum | `stable`, `test`, `experimental`, `deprecated`, `unsupported` |
| `description` | Recommended | String | What the rule detects, why it matters |
| `author` | Recommended | String | Comma-separated names |
| `date` | Recommended | `YYYY-MM-DD` | Day-of-month must be valid |
| `modified` | Optional | `YYYY-MM-DD` | Must be >= `date` |
| `references` | Optional | List of URLs | Sources, blog posts, documentation |
| `tags` | Optional | List of strings | Format: `namespace.value` (see Tags below) |
| `level` | Recommended | Enum | `informational`, `low`, `medium`, `high`, `critical` |
| `falsepositives` | Optional | List of strings | Known FP scenarios (min 2 chars each) |
| `related` | Optional | List of mappings | Cross-references to other rules |
| `scope` | Optional | List of strings | Scoping information |
| `name` | Optional | String, max 256 chars | Machine-readable name |

### Related Field

```yaml
related:
    - id: <UUIDv4>
      type: derived    # derived | obsolete | merged | renamed | similar
```

Rules with `status: deprecated` should have at least one `related` entry.

## Logsource

At least one of `category`, `product`, or `service` is required. All values must be lowercase.

```yaml
logsource:
    category: process_creation   # what kind of event
    product: windows             # which platform/product
    service: sysmon              # specific log source
    definition: >                # optional free-text for readers
        Requires Sysmon with process creation logging enabled
```

`category` describes the event type (e.g. `process_creation`, `file_event`, `network_connection`, `authentication`). `product` is the platform (e.g. `windows`, `linux`, `macos`, `aws`, `azure`). `service` narrows to a specific log source within the product.

Custom fields are allowed per the spec but may not be portable.

## Detection Block

### Parsing Rules

| YAML Structure | Interpretation |
|----------------|---------------|
| Mapping (`key: value` pairs) | `AllOf` -- all field conditions AND-linked |
| List of mappings | `AnyOf` -- each mapping OR-linked |
| List of plain values | `Keywords` -- field-agnostic search across all fields |

### Multiple Values for a Field

A list of values is OR-linked by default:

```yaml
selection:
    EventID:
        - 1
        - 4688
```

Add `|all` to AND-link values:

```yaml
selection:
    CommandLine|contains|all:
        - 'delete'
        - 'shadows'
```

### Multiple Conditions

The `condition` field can be a list, producing independent rule evaluations:

```yaml
condition:
    - selection1
    - selection2
```

### Underscore-Prefixed Identifiers

Identifiers starting with `_` are excluded from `them` and bare `all of` / `1 of` quantifiers. Use them for helper or reusable sub-detections.

## Value Types

| Type | Example | Notes |
|------|---------|-------|
| String | `'whoami'` or `whoami` | Wildcards: `*` (multi), `?` (single) |
| Integer | `4688` | Numeric matching |
| Float | `3.14` | Numeric matching |
| Boolean | `true` / `false` | Used with `exists` modifier |
| Null | `null` | Matches field absence |

### Wildcard Escaping

| Input | Parsed As |
|-------|-----------|
| `\*` | Literal `*` (not a wildcard) |
| `\?` | Literal `?` |
| `\\` | Literal `\` |
| `\W` | Literal `\W` (both chars kept) |

Backslash only escapes `*`, `?`, and `\`. This preserves Windows paths like `C:\Windows\System32`.

## Tags

Format: `namespace.value` matching `^[a-z0-9_-]+\.[a-z0-9._-]+$`.

| Namespace | Purpose | Example |
|-----------|---------|---------|
| `attack` | MITRE ATT&CK | `attack.execution`, `attack.t1059.001` |
| `car` | MITRE CAR | `car.2019-04-001` |
| `cve` | CVE identifiers | `cve.2021-44228` |
| `d3fend` | MITRE D3FEND | `d3fend.d3-psep` |
| `detection` | Detection metadata | `detection.dfir` |
| `stp` | Sigma Taxonomy Project | `stp.1a` |
| `tlp` | Traffic Light Protocol | `tlp.white` |

No duplicate tags allowed.

## Multi-Document YAML

Separate documents with `---`. Collection actions control template merging:

### action: global

Stores the document as a template that merges into all subsequent rules. The `action` key itself is removed. No rule is produced.

```yaml
action: global
logsource:
    product: windows
    category: process_creation
level: medium
---
title: Detect Cmd
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
---
title: Detect Powershell
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
```

Both rules inherit `logsource` and `level` from the global template.

### action: reset

Clears the current global template. No rule is produced.

### action: repeat

Clones the previous document, deep-merges the current document on top, then applies the global template. Useful for rules that differ only slightly.

```yaml
action: global
logsource:
    product: windows
---
title: Detect Cmd
id: detect-cmd
detection:
    selection:
        CommandLine|contains: 'cmd'
    condition: selection
---
action: repeat
title: Detect Powershell
id: detect-ps
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
```

### Merge Order

- Normal documents: `merged = deep_merge(global, document)`
- Repeat documents: `merged = deep_merge(global, deep_merge(previous, repeat_doc))`

`deep_merge` is recursive: source mappings override destination keys; non-mapping source replaces destination entirely.

## Complete Real-World Example

```yaml
title: Suspicious PowerShell Download Cradle
id: 3b6ab547-0998-4d6b-8e34-f1e7016c37a2
status: test
description: >
    Detects PowerShell download cradles using common cmdlets
    and .NET classes to fetch remote payloads.
author: Security Operations
date: 2025-03-01
modified: 2025-06-15
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1105/
tags:
    - attack.execution
    - attack.t1059.001
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_download:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'IWR '
            - 'wget '
            - 'curl '
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Invoke-RestMethod'
            - 'Start-BitsTransfer'
    selection_encoded:
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand'
        CommandLine|re: '(http|ftp)s?://'
    condition: selection_parent and (selection_download or selection_encoded)
falsepositives:
    - Legitimate admin scripts that download tools
    - Software deployment systems
level: high
```
