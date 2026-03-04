# Field Modifiers Reference

Full reference for all 30 Sigma field modifiers per the v2.1.0 specification. Modifiers are chained on the field name with `|` separators.

## Syntax

```yaml
FieldName|modifier1|modifier2: value
```

Modifiers are applied left-to-right. Some modifiers transform the value, others change matching behavior.

## Modifier Categories

### String Matching

| Modifier | Effect | Example |
|----------|--------|---------|
| `contains` | Substring match (wraps value in `*...*`) | `CommandLine\|contains: 'whoami'` |
| `startswith` | Prefix match (appends `*`) | `Image\|startswith: 'C:\Windows'` |
| `endswith` | Suffix match (prepends `*`) | `Image\|endswith: '\cmd.exe'` |

These are mutually exclusive -- do not combine them with each other.

### Value Linking

| Modifier | Effect | Example |
|----------|--------|---------|
| `all` | AND-link all values (default is OR) | `CommandLine\|contains\|all: ['delete', 'shadows']` |

Without `all`, a list of values means "match any one." With `all`, all values must match.

Do not use `all` with a single value (redundant). Do not combine `all` with `re`.

### Encoding

| Modifier | Alias | Effect |
|----------|-------|--------|
| `base64` | | Match base64-encoded form of the value |
| `base64offset` | | Match base64 at any of the 3 encoding offsets |
| `wide` | `utf16le` | Match UTF-16LE encoded form |
| `utf16be` | | Match UTF-16BE encoded form |
| `utf16` | | Match both UTF-16LE and UTF-16BE |

Encoding modifiers can be chained: `FieldName|wide|base64offset: 'payload'`

### Pattern Matching

| Modifier | Effect | Notes |
|----------|--------|-------|
| `re` | Value is a regular expression | Disables wildcard parsing (`*`, `?` are literal) |
| `cidr` | CIDR network range match | Value must be CIDR notation: `10.0.0.0/8` |

When `re` is present, the value is treated as a raw regex string. Backslash sequences are not interpreted as Sigma wildcards.

### Case Sensitivity

| Modifier | Effect |
|----------|--------|
| `cased` | Case-sensitive match (default is case-insensitive) |

### Field Existence

| Modifier | Effect | Values |
|----------|--------|--------|
| `exists` | Check whether the field exists | `true` (must exist) or `false` (must not exist) |

A lone `*` wildcard value is equivalent to `exists: true`. Prefer the explicit form.

### Placeholder

| Modifier | Effect |
|----------|--------|
| `expand` | Mark value as a placeholder for pipeline expansion |

### Field Reference

| Modifier | Effect |
|----------|--------|
| `fieldref` | Value is a field name, not a literal. Matches when the referenced field's value equals this field's value |

### Numeric Comparison

| Modifier | Effect |
|----------|--------|
| `gt` | Greater than |
| `gte` | Greater than or equal |
| `lt` | Less than |
| `lte` | Less than or equal |
| `neq` | Not equal |

Do not combine numeric modifiers with string matching modifiers (`contains`, `startswith`, `endswith`).

### Regex Flags

| Modifier | Alias | Effect |
|----------|-------|--------|
| `i` | `ignorecase` | Case-insensitive regex |
| `m` | `multiline` | Multiline mode (`^`/`$` match line boundaries) |
| `s` | `dotall` | Dot matches newline |

Regex flags require the `re` modifier to be present.

### Timestamp Parts

| Modifier | Effect |
|----------|--------|
| `minute` | Match the minute component of a timestamp field |
| `hour` | Match the hour component |
| `day` | Match the day-of-month component |
| `week` | Match the week number |
| `month` | Match the month component |
| `year` | Match the year component |

These were introduced in v2.1.0 and allow time-based filtering on timestamp fields.

---

## Incompatible Modifier Combinations

The following combinations are invalid:

| Combination | Why |
|-------------|-----|
| `contains\|startswith` | Conflicting match types |
| `contains\|endswith` | Conflicting match types |
| `startswith\|endswith` | Conflicting match types |
| `re\|contains` | Regex disables wildcard wrapping |
| `re\|startswith` | Regex disables wildcard wrapping |
| `re\|endswith` | Regex disables wildcard wrapping |
| `gt\|contains` (and other numeric + string) | Numeric and string matching conflict |
| `i` without `re` | Regex flag needs regex modifier |
| `m` without `re` | Regex flag needs regex modifier |
| `s` without `re` | Regex flag needs regex modifier |
| `all\|re` | `all` with regex is ambiguous |

## Modifier Chaining Examples

```yaml
# Substring match, all values must be present (AND)
CommandLine|contains|all:
    - 'net'
    - 'user'
    - '/add'

# Case-insensitive regex
CommandLine|re|i: 'invoke-(expression|command)'

# Base64-encoded wide string at any offset
CommandLine|wide|base64offset: 'http://evil.com'

# Windash: matches both -exec and /exec
CommandLine|windash|contains: '-exec'

# Field existence check
TargetFilename|exists: true

# Numeric comparison
EventID|gte: 4688

# Field reference: match events where SourceIP equals DestinationIP
SourceIP|fieldref: DestinationIP

# Timestamp-based detection
Timestamp|hour|gte: 22
```

## Common Patterns

### OR Values (default)

```yaml
selection:
    Image|endswith:
        - '\cmd.exe'
        - '\powershell.exe'
        - '\pwsh.exe'
```

Matches if Image ends with any of the three values.

### AND Values (with `all`)

```yaml
selection:
    CommandLine|contains|all:
        - 'net'
        - 'localgroup'
        - 'administrators'
```

Matches only if CommandLine contains all three strings.

### Negation via Condition (not a modifier)

Negation is handled in the condition expression, not via modifiers:

```yaml
detection:
    selection:
        EventID: 1
    filter:
        User: 'SYSTEM'
    condition: selection and not filter
```
