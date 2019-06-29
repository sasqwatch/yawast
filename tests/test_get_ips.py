from unittest import TestCase
from yawast.scanner.plugins.dns import basic


class TestGetIps(TestCase):
    def test_get_ips_ac(self):
        res = basic.get_ips("adamcaudill.com")

        self.assertEqual(4, len(res))
