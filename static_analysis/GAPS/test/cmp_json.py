import unittest
import json
import sys
import os
import tempfile

from gaps.gaps_manager import GapsManager

###############################################################################
# LOGGING
###############################################################################

import logging

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)
# logging.basicConfig(level=logging.DEBUG)

###############################################################################
# GLOBALS
###############################################################################

DIR = os.path.dirname(os.path.abspath(__file__))

###############################################################################
# CODE
###############################################################################


class TestJson(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def _setup(test_name, tmp_out_dir) -> GapsManager:
        # get method name and strip the prefix to obtain the dir for the test
        # case

        dalvik_path = os.path.join(DIR, test_name, "classes.dex")
        gaps = GapsManager(dalvik_path, tmp_out_dir.name)
        return gaps

    def _check(self, test_name, tmp_out_dir):
        json_out_name = os.path.join(test_name, "gaps-out.json")
        expected_output = {}
        with open(json_out_name, "r") as expected_file:
            expected_output = json.load(expected_file)

        comparee_output = {}

        comparee_file_path = os.path.join(
            tmp_out_dir.name, "classes-instr.json"
        )
        with open(comparee_file_path, "r") as comparee_file:
            comparee_output = json.load(comparee_file)
        self.assertDictEqual(
            expected_output,
            comparee_output,
            "output differs from expected output",
        )

    def test_byte_array_length_propagation(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)

    def test_byte_array(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)

    def test_primitive_constant(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)

    def test_string_retrieval(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)

    def test_var_propagation(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)

    def test_file_path(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)

    def test_dependencies(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)

    def test_overloading_jni(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)

    def test_intra_var_propagation(self):
        test_method_name = sys._getframe().f_code.co_name
        test_name = test_method_name.removeprefix("test_")
        tmp_out_dir = tempfile.TemporaryDirectory(prefix="gaps_")
        gaps = self._setup(test_name, tmp_out_dir)
        gaps.start_path_finding()
        self._check(test_name, tmp_out_dir)


if __name__ == "__main__":
    unittest.main()
