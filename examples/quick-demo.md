# Quick demo

This safe, temporary example lets you see the scanner flag a hardcoded credential without modifying a project:

```bash
cat > /tmp/psylinks-demo.py <<'PY'
API_KEY = "replace-this-demo-value"
print(API_KEY)
PY

python3 scripts/scan.py /tmp/psylinks-demo.py --no-network --no-audit
rm -f /tmp/psylinks-demo.py
```

The result should identify the credential-looking assignment and explain that the value should move to an environment variable or secrets manager. The demo value is intentionally fake; never use real credentials in a test file.

For a machine-readable result, add `--json`. For a project scan, replace `/tmp/psylinks-demo.py` with your project path and review every finding before making changes.
