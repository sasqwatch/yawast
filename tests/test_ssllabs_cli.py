import json
import os
from unittest import TestCase

from tests import utils
from yawast.scanner.cli.ssl_labs import (
    _get_cert_info,
    _get_protocol_info,
    _get_vulnerability_info,
)


class TestSslLabsCLI(TestCase):
    def test__get_cert_info(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/ssl_labs_analyze_data.json")
        with open(path) as json_file:
            body = json.load(json_file)

        try:
            for ep in body["endpoints"]:
                with utils.capture_sys_output() as (stdout, stderr):
                    _get_cert_info(body, ep, "http://adamcaudill.com")
        except Exception as error:
            print(error)
            self.assertIsNone(error)

    def test__get_protocol_info(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/ssl_labs_analyze_data.json")
        with open(path) as json_file:
            body = json.load(json_file)

        try:
            for ep in body["endpoints"]:
                with utils.capture_sys_output() as (stdout, stderr):
                    _get_protocol_info(ep, "http://adamcaudill.com")
        except Exception as error:
            print(error)
            self.assertIsNone(error)

    def test__get_vulnerability_info(self):
        target_dir = os.path.dirname(os.path.realpath("__file__"))
        path = os.path.join(target_dir, "tests/test_data/ssl_labs_analyze_data.json")
        with open(path) as json_file:
            body = json.load(json_file)

        try:
            for ep in body["endpoints"]:
                with utils.capture_sys_output() as (stdout, stderr):
                    _get_vulnerability_info(ep, "http://adamcaudill.com")
        except Exception as error:
            print(error)
            self.assertIsNone(error)
