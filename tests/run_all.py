#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

modules = ["test_mgr", "test_api", "test_controller"]
loader = unittest.TestLoader()
suite = unittest.TestSuite()
for name in modules:
    suite.addTests(loader.loadTestsFromName(name))
runner = unittest.TextTestRunner(verbosity=1)
result = runner.run(suite)
total = result.testsRun
failed = len(result.failures) + len(result.errors)
print("mihomo-pool tests: %d/%d passed" % (total - failed, total))
sys.exit(1 if failed else 0)
