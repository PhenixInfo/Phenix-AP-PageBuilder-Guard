---
name: gstack
version: project-adapter-1
description: Project-local adapter for structured engineering review, security review, investigation, QA and release gates.
---

# gstack project adapter

Use this skill for Phenix AP PageBuilder Guard development.

Route work as follows:

- code/diff review -> review correctness, trust boundaries, side effects, rollback and compatibility;
- security review -> trace request input to vulnerable sink, verify defense in depth and attempt bypass combinations;
- bug -> reproduce first, reduce to a deterministic regression case, then fix;
- QA/release -> execute AGENTS.md gates, including static checks, fuzzing and the real AP archive matrix;
- performance -> measure before adding caching or complexity.

Do not add architecture merely because a pattern is fashionable. For this project the release gate is evidence: tests, exact rollback hashes, validator compliance, and no scope growth.

When a security-sensitive change cannot be verified, stop the release rather than guessing.
