#!/usr/bin/env python3
# Copyright (c) 2026 Foley IT. AGPL-3.0, see LICENSE.
"""Dry-run tests of crowdsec-setup.sh: the Dunree names for a new setup, and the file an earlier run of
the earlier helper wrote is kept.   python3 contrib/crowdsec/test_crowdsec_setup.py"""
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "crowdsec-setup.sh")


def debian_like():
    try:
        txt = open("/etc/os-release").read().lower()
    except OSError:
        return False
    return "debian" in txt or "ubuntu" in txt


@unittest.skipUnless(debian_like() and shutil.which("bash"), "the script only runs on Debian or Ubuntu")
class DryRun(unittest.TestCase):
    def run_script(self, acquis_dir):
        env = dict(os.environ, CROWDSEC_ACQUIS_DIR=acquis_dir)
        r = subprocess.run(["bash", SCRIPT, "--dry-run", "--log-dir", "/opt/dunree/log"], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout)
        return r.stdout

    def test_new_setup_uses_dunree_names(self):
        with tempfile.TemporaryDirectory() as d:
            out = self.run_script(d)
        self.assertIn("write %s/dunree.yaml" % d, out)
        self.assertIn("type: dunree", out)
        self.assertIn("cscli bouncers add dunree-", out)
        self.assertNotIn("zoraxy", out.lower())

    def test_existing_zoraxy_acquisition_file_is_kept(self):  # legacy-compat
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "zoraxy.yaml"), "w").close()
            out = self.run_script(d)
        self.assertIn("%s/zoraxy.yaml" % d, out)
        self.assertNotIn("%s/dunree.yaml" % d, out)


if __name__ == "__main__":
    unittest.main()
