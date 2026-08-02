# User Instruction Memory

This file records user instructions, preferences, and teachings for reference in future interactions.

## Format

### User Instruction Entry
User instruction entries should follow this format:

[User Instruction Summary]
- Date: [YYYY-MM-DD]
- Context: [Mentioned scenario or time]
- Instructions:
  - [Content of user teaching or instruction, described line by line]

### Project Knowledge Entry
Entries discovered by the Agent during task execution should follow this format:

[Project Knowledge Summary]
- Date: [YYYY-MM-DD]
- Context: Discovered by Agent while performing [specific task description]
- Category: [Operations & Deployment|Build Methods|Testing Methods|Troubleshooting & Debugging|Workflow & Collaboration|Environment Configuration]
- Instructions:
  - [Specific knowledge points, described line by line]

## Deduplication Strategy
- Before adding a new entry, check for similar or identical instructions.
- If a duplicate is found, skip the new entry or merge it with the existing one.
- When merging, update the context or date information.
- This helps avoid redundant entries and keeps the memory file tidy.

## Entries

[Project Knowledge Summary]
- Date: 2026-08-02
- Context: Discovered by Agent while performing multi-node egress feature integration testing
- Category: Environment Configuration
- Instructions:
  - This environment has no openvpn binary installed. Real tunnel integration tests are impossible; validate core logic via module import + mock process tests instead.
  - The web UI HTTP handler requires the configured secret_path prefix (e.g. /testsecret/api/...) and CSRF token header (X-CSRF-Token) for POST requests; a plain request without these returns 404/403.
  - `_cached_ui_config` is not a variable name in vpngate_manager.py; the actual cache is `_config_cache` (module-level dict) with `_config_cache_time`.
  - API base path is secret-path prefixed; test requests must include the prefix and a valid session cookie.
