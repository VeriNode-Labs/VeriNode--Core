#!/usr/bin/env python3
"""
Automated Validator for Docker Image Layer Caching Configuration
Verifies Dockerfile syntax, multi-stage caching isolation, .dockerignore boundaries,
GitHub Actions BuildKit cache integration, and canary deployment runbooks.
"""

import os
import re
import sys

def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dockerfile_path = os.path.join(root, "Dockerfile")
    dockerignore_path = os.path.join(root, ".dockerignore")
    workflow_path = os.path.join(root, ".github", "workflows", "docker-image.yml")
    docs_path = os.path.join(root, "docs", "docker-ci-cache.md")

    # 1. Validate Dockerfile
    if not os.path.exists(dockerfile_path):
        print("ERROR: Dockerfile missing!", file=sys.stderr)
        sys.exit(1)

    with open(dockerfile_path) as f:
        df_content = f.read()

    assert re.search(r"^# syntax=docker/dockerfile:1\.7", df_content, re.MULTILINE), \
        "Dockerfile must opt into BuildKit 1.7 syntax"
    assert "FROM ${RUST_IMAGE} AS base" in df_content, "Dockerfile must define base stage"
    assert "FROM base AS deps" in df_content, "Dockerfile must isolate dependency caching layer"
    assert "FROM deps AS builder" in df_content, "Dockerfile must compile in builder stage"
    assert "FROM ${RUNTIME_IMAGE} AS runtime" in df_content, "Dockerfile must define lean runtime stage"
    assert "USER verinode" in df_content, "Runtime container must execute under unprivileged user"

    # 2. Validate .dockerignore
    if not os.path.exists(dockerignore_path):
        print("ERROR: .dockerignore missing!", file=sys.stderr)
        sys.exit(1)

    with open(dockerignore_path) as f:
        di_content = f.read()

    for item in [".git", "target", "tests", "docs"]:
        assert item in di_content, f".dockerignore must exclude {item}"

    # 3. Validate GitHub Actions workflow
    if not os.path.exists(workflow_path):
        print("ERROR: .github/workflows/docker-image.yml missing!", file=sys.stderr)
        sys.exit(1)

    with open(workflow_path) as f:
        wf_content = f.read()

    assert "cache-from: type=gha,scope=" in wf_content, "Workflow must restore BuildKit cache from gha"
    assert "cache-to: type=gha,scope=" in wf_content, "Workflow must save BuildKit cache to gha"
    assert "cron: '17 3 * * 1'" in wf_content, "Workflow must schedule weekly cache warm-up"
    assert "canary-analysis:" in wf_content, "Workflow must declare canary-analysis validation job"

    # 4. Validate documentation
    if not os.path.exists(docs_path):
        print("ERROR: docs/docker-ci-cache.md missing!", file=sys.stderr)
        sys.exit(1)

    with open(docs_path) as f:
        doc_content = f.read().lower()

    assert "blue-green" in doc_content, "Runbook must document blue-green deployment posture"
    assert "canary" in doc_content, "Runbook must document canary analysis"
    assert "security review" in doc_content, "Runbook must document security review gates"

    print("✅ All Docker Image Layer Caching validations passed successfully!")

if __name__ == "__main__":
    main()
