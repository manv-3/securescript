"""
Unit test wrapping the Automated Penetration Testing Harness.
"""

from securescript.core.penetration import PenetrationTester


def test_full_penetration_suite_efficacy():
    tester = PenetrationTester()
    report = tester.run_full_penetration_suite()

    assert report.total_attacks_attempted >= 8
    assert report.defense_efficacy_rate == 100.0
    assert report.benign_passed_http_200 == report.benign_requests_attempted
    assert report.attacks_blocked_http_403 > 0
    assert report.attacks_mitigated_csp > 0
