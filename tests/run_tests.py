#!/usr/bin/env python3
"""
TEST RUNNER FOR URBAN MOBILITY BACKEND SYSTEM

Runs all pytest-based unit and integration tests.
Uses pytest for test discovery and execution with coverage reporting.

Usage:
    python run_tests.py                 # Run all tests
    python run_tests.py --unit          # Run only unit tests
    python run_tests.py --integration   # Run only integration tests
    python run_tests.py --verbose       # Run with verbose output
    python run_tests.py --no-coverage   # Run without coverage report
"""

import sys
import subprocess
import argparse


def run_pytest(args):
    """Run pytest with the specified arguments."""
    # Build pytest command
    pytest_args = ["pytest"]

    # Add test directory/markers based on arguments
    if args.unit:
        pytest_args.extend(["-m", "unit"])
    elif args.integration:
        pytest_args.extend(["-m", "integration"])
    else:
        # Run all tests in tests directory
        pytest_args.append("tests/")

    # Add verbose flag if requested
    if args.verbose:
        pytest_args.append("-v")
    else:
        # Default verbosity
        pytest_args.append("-v")

    # Add coverage options unless disabled
    if not args.no_coverage:
        pytest_args.extend(
            [
                "--cov=src",
                "--cov-report=html:tests/htmlcov",
                "--cov-report=term-missing",
                "--cov-config=tests/pytest.ini",
            ]
        )

    # Add other useful options
    pytest_args.extend(["--strict-markers", "--tb=short"])

    # Run pytest
    print("=" * 80)
    print("URBAN MOBILITY BACKEND SYSTEM - TEST RUNNER")
    print("=" * 80)
    print(f"\nRunning: {' '.join(pytest_args)}\n")
    print("=" * 80)

    result = subprocess.run(pytest_args)
    return result.returncode


def main():
    """Main entry point for test runner."""
    parser = argparse.ArgumentParser(
        description="Run tests for Urban Mobility Backend System"
    )
    parser.add_argument("--unit", "-u", help="Run only unit tests", action="store_true")
    parser.add_argument(
        "--integration", "-i", help="Run only integration tests", action="store_true"
    )
    parser.add_argument(
        "--verbose", "-v", help="Enable verbose output", action="store_true"
    )
    parser.add_argument(
        "--no-coverage", help="Disable coverage reporting", action="store_true"
    )

    args = parser.parse_args()

    # Run tests
    exit_code = run_pytest(args)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
