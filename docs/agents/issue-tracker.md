# Issue Tracker

GitHub Issues in `Anionix/diagnostic-triage` are the canonical work tracker.

- Specifications and implementation tasks are issues.
- Agent-ready work carries `ready-for-agent`.
- Pull requests are implementation artifacts, not an incoming request queue.
- Close an issue only after merged behavior is verified on `main`.

After every merge, inspect all review threads. Resolve or outdate completed
threads. For a remaining defect, create an idempotent `bug` issue, reply with
its URL, then resolve or outdate the original thread. Fixes start from the
latest `origin/main` and never stack on the merged branch.
