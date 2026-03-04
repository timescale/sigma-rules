# Sigma Rules Skill

An [Agent Skill](https://agentskill.sh/) for authoring [Sigma](https://github.com/SigmaHQ/sigma) detection rules, correlation rules, filter rules, and processing pipelines.

## What This Skill Does

This skill teaches AI agents the full [Sigma v2.1.0 specification](https://github.com/SigmaHQ/sigma-specification) so they can:

- Write correct detection rules from natural language descriptions
- Create correlation rules (event_count, value_count, temporal, and 5 more types)
- Author filter rules for centralized tuning
- Build processing pipelines for field mapping (ECS, Splunk CIM, etc.)
- Use proper field modifiers, condition expressions, and multi-document YAML
- Validate rules against the specification checklist

## Install

```bash
npx skills add timescale/sigma-rules -g -y
```

Or install for a specific agent:

```bash
npx skills add timescale/sigma-rules -g -a cursor -y
npx skills add timescale/sigma-rules -g -a claude-code -y
```

## Structure

```
sigma-rules/
├── SKILL.md                          # Main skill — templates, examples, checklist
└── references/
    ├── detection-rules.md            # Detection rule format deep dive
    ├── correlation-rules.md          # All 8 correlation types with examples
    ├── filter-rules.md               # Filter rule format and usage
    ├── pipelines.md                  # Pipeline transforms and conditions
    ├── modifiers.md                  # All 30 field modifiers
    └── condition-syntax.md           # Condition expression grammar
```

The main `SKILL.md` covers the essential authoring workflow with templates and worked examples. Reference files provide deeper detail and are loaded on demand.

## Coverage

- Sigma Specification v2.1.0 (backward-compatible with v2.0.0)
- 30 field modifiers with compatibility rules
- 8 correlation types (event_count, value_count, temporal, temporal_ordered, value_sum, value_avg, value_percentile, value_median)
- 26 pipeline transformation types
- Multi-document YAML (global, reset, repeat actions)
- Condition expression grammar (not > and > or, quantifiers, wildcards)

## References

- [Sigma Specification](https://github.com/SigmaHQ/sigma-specification)
- [SigmaHQ Rule Repository](https://github.com/SigmaHQ/sigma)
- [pySigma](https://github.com/SigmaHQ/pySigma)

## License

MIT
