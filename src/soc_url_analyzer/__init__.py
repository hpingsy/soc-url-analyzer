"""Offline URL threat analysis. No DNS lookups or HTTP requests are performed."""

from .analyzer import analyze_url

__all__ = ["analyze_url"]
