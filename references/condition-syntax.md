# Condition Expression Syntax

Full reference for Sigma condition expressions per the v2.1.0 specification.

## Overview

The `condition` field in a detection block combines named detection identifiers with boolean logic and quantifiers.

```yaml
detection:
    selection:
        EventID: 1
    filter:
        User: 'SYSTEM'
    condition: selection and not filter
```

## Operator Precedence

| Precedence (highest first) | Operator | Type |
|---------------------------|----------|------|
| 1 | `not` | Prefix (unary) |
| 2 | `and` | Infix (binary), left-associative |
| 3 | `or` | Infix (binary), left-associative |

`a or not b and c` parses as `a or ((not b) and c)`.

Use parentheses to override: `(a or b) and not c`.

## Boolean Operators

```yaml
# AND: all must match
condition: selection1 and selection2

# OR: any must match
condition: selection1 or selection2

# NOT: negate
condition: selection and not filter

# Parentheses: grouping
condition: (selection1 or selection2) and not filter

# Complex
condition: selection_parent and (selection_download or selection_encoded) and not filter
```

Nested same-type binary operators are flattened: `a and b and c` becomes `And([a, b, c])`, not `And(a, And(b, c))`.

## Quantifiers

Quantifiers aggregate multiple detection identifiers.

| Quantifier | Meaning |
|-----------|---------|
| `1 of X` | At least one of the matched identifiers fires |
| `any of X` | Same as `1 of X` |
| `all of X` | All matched identifiers must fire |
| `N of X` | At least N of the matched identifiers fire |

Where `X` is one of:
- A wildcard pattern: `selection*`, `filter_*`
- `them` -- all identifiers except `_`-prefixed ones

### Examples

```yaml
# At least one selection fires
condition: 1 of selection*

# All selections must fire
condition: all of selection*

# At least 2 of the matched identifiers
condition: 2 of selection*

# Any named identifier (except _-prefixed)
condition: 1 of them

# All identifiers must fire
condition: all of them
```

### Wildcard Patterns

`selection*` matches identifiers named `selection`, `selection1`, `selection_cmd`, etc. The `*` matches any suffix.

### `them` Keyword

`them` matches all detection identifiers in the block **except** those starting with `_`:

```yaml
detection:
    _helper:
        ParentImage|endswith: '\services.exe'
    selection1:
        Image|endswith: '\svchost.exe'
    selection2:
        Image|endswith: '\lsass.exe'
    condition: 1 of them
```

Here `1 of them` matches `selection1` or `selection2` but ignores `_helper`. Use `_`-prefixed identifiers for reusable sub-detections that should not be included in quantifier aggregation.

## Combining Quantifiers with Boolean Logic

```yaml
condition: 1 of selection* and not 1 of filter*
condition: all of selection* or keywords
condition: (1 of selection_network* or 1 of selection_process*) and not filter
```

## Multiple Conditions

The `condition` field can be a YAML list, producing independent rule evaluations:

```yaml
detection:
    selection1:
        EventID: 1
    selection2:
        EventID: 4688
    condition:
        - selection1
        - selection2
```

Each condition is evaluated separately, potentially producing multiple matches from a single rule.

## Parsing Notes

- Identifiers cannot be Sigma keywords (`and`, `or`, `not`, `of`, `them`, `all`, `any`). An identifier like `and_filter` is valid because the parser uses lookahead to distinguish keywords from identifier prefixes.
- Whitespace between operators and operands is required: `aand b` is an identifier, not `a and b`.
- Condition expressions are case-sensitive: `AND` is not recognized as a boolean operator (use lowercase `and`).

## Correlation Condition Expressions

In temporal correlation rules, the condition is a string referencing rule IDs (not detection identifiers):

```yaml
correlation:
    type: temporal
    rules:
        - rule-a
        - rule-b
    condition: "rule-a and rule-b"
```

This uses the same boolean syntax (`and`, `or`, `not`, parentheses) but over rule references instead of detection names.
