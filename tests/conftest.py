"""Keep the hand-run Docker integration harness out of pytest collection.
Run it separately with: python tests/test_gateway.py
"""
collect_ignore = ["test_gateway.py"]
