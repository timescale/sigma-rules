# Processing Pipelines Reference

Full reference for Sigma processing pipelines. Pipelines transform Sigma rule ASTs before evaluation or backend conversion -- typically for field name mapping between generic Sigma fields and backend-specific schemas.

## Pipeline Structure

```yaml
name: <pipeline name>
priority: <integer>              # lower runs first, default 0
vars:                            # variables for %name% placeholder expansion
  var_name: <string or list>
transformations:                 # ordered list of transformation items
  - id: <optional string>       # for processing_item_applied conditions
    type: <transformation_type>
    # ... type-specific parameters
    rule_conditions: []          # optional: all must match for transform to apply
    rule_cond_expression: ""     # optional: logical expression over conditions
    detection_item_conditions: []
    field_name_conditions: []
    field_name_cond_not: false   # negate field name conditions
finalizers:                      # for query backends (not used in eval mode)
  - type: <concat|json|template>
```

Multiple pipelines are sorted by `priority` (ascending) and applied in order.

---

## Transformation Types (26)

### Field Transformations

| Type | Parameters | Effect |
|------|-----------|--------|
| `field_name_mapping` | `mapping: {old: new}` | Rename specific fields |
| `field_name_prefix_mapping` | `mapping: {prefix: replacement}` | Replace field name prefixes |
| `field_name_prefix` | `prefix: string` | Add prefix to all field names |
| `field_name_suffix` | `suffix: string` | Add suffix to all field names |
| `field_name_transform` | `transform_func: lower\|upper\|title\|snake_case` | Transform field name casing |
| `add_field` | `field: string` | Add a field to detection items |
| `remove_field` | `field: string` | Remove a field from detection items |
| `set_field` | `fields: [list]` | Set detection item fields |

### Value Transformations

| Type | Parameters | Effect |
|------|-----------|--------|
| `replace_string` | `regex`, `replacement`, `skip_special: bool` | Regex replacement in values |
| `map_string` | `mapping: {val: [alternatives]}` | Map values to alternatives |
| `set_value` | `value: any` | Set detection item value |
| `convert_type` | `target_type: str\|int\|float\|bool` | Convert value type |
| `regex` | (none) | Convert plain strings to regex |
| `case_transformation` | `case_type: lower\|upper\|snake_case` | Transform value casing |
| `hashes_fields` | `valid_hash_algos: [list]`, `field_prefix`, `drop_algo_prefix: bool` | Normalize hash field names |

### Detection Structure Transformations

| Type | Parameters | Effect |
|------|-----------|--------|
| `drop_detection_item` | (none) | Remove matching detection items |
| `add_condition` | `conditions: {field: value}`, `negated: bool` | Inject extra field conditions |
| `change_logsource` | `category`, `product`, `service` | Rewrite logsource fields |

### Placeholder Transformations

| Type | Parameters | Effect |
|------|-----------|--------|
| `value_placeholders` | (none) | Expand `%name%` from pipeline `vars` |
| `wildcard_placeholders` | (none) | Replace unresolved `%name%` with `*` |
| `query_expression_placeholders` | `expression: string` | Backend query expression (no-op for eval) |

### State and Control Transformations

| Type | Parameters | Effect |
|------|-----------|--------|
| `set_state` | `key`, `value` | Store key-value in pipeline state |
| `set_custom_attribute` | `attribute`, `value` | Set custom attribute on the rule |
| `rule_failure` | `message` | Fail the rule with message |
| `detection_item_failure` | `message` | Fail a detection item with message |
| `nest` | `items` or `transformations: [list]` | Group transformations |

---

## Condition Types

Transformations are gated by conditions. All conditions in a list are AND-linked by default. Use `rule_cond_expression` for custom logic.

### Rule Conditions (`rule_conditions`)

Applied at the rule level -- the transformation only runs if the rule matches.

| Type | Parameters | Matches When |
|------|-----------|-------------|
| `logsource` | `category`, `product`, `service` | Rule logsource matches (omitted fields match any) |
| `contains_detection_item` | `field`, `value` (optional) | Rule has detection with that field (and value) |
| `processing_item_applied` | `processing_item_id` | An earlier transform with that `id` was applied |
| `processing_state` | `key`, `val` | Pipeline state key equals value |
| `is_sigma_rule` | (none) | Document is a detection rule |
| `is_sigma_correlation_rule` | (none) | Document is a correlation rule |
| `rule_attribute` | `attribute`, `value` | Rule metadata matches (level, status, author, title, id, date, description) |
| `tag` | `tag` | Rule has this tag |

### Detection Item Conditions (`detection_item_conditions`)

Applied per detection item within a rule.

| Type | Parameters | Matches When |
|------|-----------|-------------|
| `match_string` | `pattern`, `negate` | Value matches regex pattern |
| `is_null` | `negate` | Value is null |
| `processing_item_applied` | `processing_item_id` | Transform was applied to this item |
| `processing_state` | `key`, `val` | Pipeline state matches |

### Field Name Conditions (`field_name_conditions`)

Applied per field name. Use `field_name_cond_not: true` to negate.

| Type | Parameters | Matches When |
|------|-----------|-------------|
| `include_fields` | `fields: [list]`, `match_type: plain\|regex` | Field name is in the list |
| `exclude_fields` | `fields: [list]`, `match_type: plain\|regex` | Field name is not in the list |
| `processing_item_applied` | `processing_item_id` | Transform was applied |
| `processing_state` | `key`, `val` | Pipeline state matches |

### Rule Condition Expression

Override the default AND behavior with `rule_cond_expression`:

```yaml
rule_conditions:
  - type: logsource
    product: windows
  - type: tag
    tag: attack.execution
rule_cond_expression: "cond_0 and not cond_1"
```

Conditions are referenced as `cond_0`, `cond_1`, ... by index. Supports `and`, `or`, `not`, and parentheses.

---

## Common Pipeline Patterns

### ECS Field Mapping

```yaml
name: Elastic Common Schema
priority: 10
transformations:
  - type: field_name_mapping
    mapping:
      CommandLine: process.command_line
      Image: process.executable
      ParentImage: process.parent.executable
      User: user.name
      SourceIP: source.ip
      DestinationIP: destination.ip
      DestinationPort: destination.port
    rule_conditions:
      - type: logsource
        product: windows
```

### Conditional Transform with State

```yaml
name: Stateful Pipeline
transformations:
  - id: windows-mapped
    type: field_name_mapping
    mapping:
      CommandLine: process.command_line
    rule_conditions:
      - type: logsource
        product: windows
  - type: field_name_prefix
    prefix: "winlog."
    rule_conditions:
      - type: processing_item_applied
        processing_item_id: windows-mapped
```

### Drop Unsupported Detection Items

```yaml
name: Drop Unsupported
transformations:
  - type: drop_detection_item
    field_name_conditions:
      - type: include_fields
        fields:
          - Imphash
          - md5
        match_type: plain
```

### Placeholder Expansion

```yaml
name: Placeholder Resolution
vars:
  admin_users:
    - Administrator
    - Domain Admins
    - Enterprise Admins
transformations:
  - type: value_placeholders
  - type: wildcard_placeholders
```

### Logsource Rewrite

```yaml
name: Splunk Logsource
transformations:
  - type: change_logsource
    category: endpoint
    product: splunk
    rule_conditions:
      - type: logsource
        product: windows
        category: process_creation
```

### Custom Attributes

```yaml
name: Engine Config
transformations:
  - type: set_custom_attribute
    attribute: rsigma.timestamp_field
    value: event.ingested
  - type: set_custom_attribute
    attribute: rsigma.suppress
    value: 5m
```

---

## Finalizers

Finalizers produce final query output. They are parsed from the pipeline YAML but not used in evaluation mode (only relevant for query backends).

| Type | Parameters | Effect |
|------|-----------|--------|
| `concat` | `separator`, `prefix`, `suffix` | Concatenate query parts |
| `json` | `indent` | Output as JSON |
| `template` | `template` | Apply a template string |
