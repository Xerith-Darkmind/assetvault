"""Shared error types. Messages are fixed phrases; callers scrub before they store or print them."""

class OpsError(Exception):
    pass

class MergeError(Exception):
    pass
