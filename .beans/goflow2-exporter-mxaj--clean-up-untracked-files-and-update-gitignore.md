---
# goflow2-exporter-mxaj
title: Clean up untracked files and update .gitignore
status: draft
type: task
priority: low
created_at: 2026-01-19T06:42:30Z
updated_at: 2026-01-19T06:42:30Z
---

Several untracked files and directories exist in the repo that should be either added to .gitignore or removed:

**Untracked items:**
- `flowlogs`, `flowlogs2` - Likely test/sample flow data
- `old.json` - Likely temporary file
- `resources/` - Contains Grafana resource exports (Dashboards, Checks, Folders, etc.)
- `.claude/` - Claude Code configuration (should probably be gitignored)
- `.beans.yml` - beans issue tracker config (may want to track or ignore)

## Checklist
- [ ] Determine which files are temporary test data (safe to delete)
- [ ] Determine which files should be added to .gitignore
- [ ] Update .gitignore accordingly
- [ ] Remove any files that shouldn't exist
