# Bridge Recipe Specification (`appbridge.toml`)

Schema Version: `1.0`

Bridge Recipes provide a declarative, validated, and reproducible specification for cross-platform application portability.

## Security Guarantees

- Validated by `bridge_spec::BridgeRecipe::validate`.
- Rejects shell metacharacters (`;`, `|`, `&`, `` ` ``, `$`, `<`, `>`) and path traversal (`..`) in executable paths and arguments.
- Blocks dynamic linker injection variables (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`).
- Never executes arbitrary inline shell scripts.
