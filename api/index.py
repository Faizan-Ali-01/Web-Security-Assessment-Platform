"""Vercel entry point: exposes the Flask app from backend/app.py."""
import os
import sys

# Make the project root importable (burp_parser, database, scanner live there).
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from backend.app import app  # noqa: E402,F401
