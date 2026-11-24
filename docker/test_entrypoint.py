#!/usr/bin/env python3
# Copyright (c) 2026 Foley IT. AGPL-3.0, see LICENSE.
"""Tests for entrypoint.py: the Dunree layout is used when it is there, the older one otherwise.
    python3 docker/test_entrypoint.py"""
import importlib.util
import os
import unittest

spec = importlib.util.spec_from_file_location("entrypoint", os.path.join(os.path.dirname(os.path.abspath(__file__)), "entrypoint.py"))
ep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ep)


class Layout(unittest.TestCase):
    def test_dunree_image(self):
        self.assertEqual(ep.base_dir(lambda p: p == "/opt/dunree"), "/opt/dunree")
        self.assertEqual(ep.program(lambda n: "/usr/local/bin/dunree" if n == "dunree" else None), "dunree")

    def test_image_built_from_an_older_dockerfile(self):  # legacy-compat
        self.assertEqual(ep.base_dir(lambda p: False), "/opt/zoraxy")
        self.assertEqual(ep.program(lambda n: None), "zoraxy")


if __name__ == "__main__":
    unittest.main()
