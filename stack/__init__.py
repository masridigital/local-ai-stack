"""Local AI stack policy gateway.

The gateway is the tested choke point in front of LiteLLM. It fail-closes
when Presidio cannot mask a request, and it refuses routes, backends, and
features that are outside the Phase 1 allowlist.
"""
