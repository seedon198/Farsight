"""Local-first web UI for FARSIGHT.

Wraps the existing async scan modules with a FastAPI server and a
WebSocket-driven progress UI, for live demo use. Does not modify or
depend on farsight/cli/scan.py.
"""
