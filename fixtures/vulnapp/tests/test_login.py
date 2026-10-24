"""Fixture test file with a dummy credential (should be triaged as false positive)."""
TEST_PASSWORD = "password123-test-only"


def test_placeholder():
    assert TEST_PASSWORD
