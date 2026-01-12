#!/usr/bin/env python3
"""
Phishing Shield - Email Test Runner

Tests the /scan API endpoint with sample emails from test_email_data folder.
Generates a report showing accuracy for each threat category.

Usage:
    python test_emails.py                    # Test all categories
    python test_emails.py --category phishing  # Test specific category
    python test_emails.py --limit 10         # Limit emails per category
    python test_emails.py --verbose          # Show detailed output
"""

import asyncio
import json
import httpx
import argparse
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


# Configuration
API_URL = "http://localhost:8000"
SCAN_ENDPOINT = "/scan"
TEST_DATA_DIR = Path(__file__).parent / "test_email_data"

# Colors for terminal output
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    END = "\033[0m"


@dataclass
class TestResult:
    email_id: str
    category: str
    expected_threat: str
    actual_threat: str
    expected_is_phishing: bool
    actual_is_phishing: bool
    confidence: float
    reason: str
    passed: bool
    response_time_ms: float


def load_test_data(category: Optional[str] = None) -> dict:
    """Load test email data from JSON files"""
    test_files = {
        "phishing": "phishing_emails.json",
        "tech_support": "tech_support_emails.json",
        "scareware": "scareware_emails.json",
        "benign": "safe_emails.json"
    }
    
    data = {}
    
    for cat, filename in test_files.items():
        if category and cat != category:
            continue
            
        filepath = TEST_DATA_DIR / filename
        if filepath.exists():
            with open(filepath, "r") as f:
                data[cat] = json.load(f)
        else:
            print(f"{Colors.YELLOW}Warning: {filename} not found{Colors.END}")
    
    return data


async def test_email(client: httpx.AsyncClient, email: dict, expected: dict) -> TestResult:
    """Test a single email against the API"""
    start_time = time.time()
    
    payload = {
        "sender_email": email.get("sender_email", ""),
        "links": email.get("links", []),
        "email_subject": email.get("email_subject", ""),
        "email_snippet": email.get("email_snippet", "")
    }
    
    try:
        response = await client.post(
            f"{API_URL}{SCAN_ENDPOINT}",
            json=payload,
            timeout=30.0
        )
        response_time_ms = (time.time() - start_time) * 1000
        
        if response.status_code != 200:
            return TestResult(
                email_id=email.get("id", "unknown"),
                category=expected.get("threat_type", "unknown"),
                expected_threat=expected.get("threat_type", "unknown"),
                actual_threat="error",
                expected_is_phishing=expected.get("is_phishing", False),
                actual_is_phishing=False,
                confidence=0.0,
                reason=f"HTTP {response.status_code}",
                passed=False,
                response_time_ms=response_time_ms
            )
        
        result = response.json()
        
        # Determine if test passed
        # For threats (phishing, tech_support, scareware): is_phishing should be True
        # For benign: is_phishing should be False
        expected_is_phishing = expected.get("is_phishing", False)
        actual_is_phishing = result.get("is_phishing", False)
        
        # Primary check: is_phishing matches expected
        passed = expected_is_phishing == actual_is_phishing
        
        return TestResult(
            email_id=email.get("id", "unknown"),
            category=expected.get("threat_type", "unknown"),
            expected_threat=expected.get("threat_type", "unknown"),
            actual_threat=result.get("threat_type", "unknown"),
            expected_is_phishing=expected_is_phishing,
            actual_is_phishing=actual_is_phishing,
            confidence=result.get("confidence", 0.0),
            reason=result.get("reason", ""),
            passed=passed,
            response_time_ms=response_time_ms
        )
        
    except Exception as e:
        response_time_ms = (time.time() - start_time) * 1000
        return TestResult(
            email_id=email.get("id", "unknown"),
            category=expected.get("threat_type", "unknown"),
            expected_threat=expected.get("threat_type", "unknown"),
            actual_threat="error",
            expected_is_phishing=expected.get("is_phishing", False),
            actual_is_phishing=False,
            confidence=0.0,
            reason=str(e),
            passed=False,
            response_time_ms=response_time_ms
        )


async def run_tests(
    category: Optional[str] = None,
    limit: Optional[int] = None,
    verbose: bool = False
) -> dict:
    """Run all tests and return results"""
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}           PHISHING SHIELD - EMAIL TEST RUNNER{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}\n")
    
    # Check API health first
    async with httpx.AsyncClient() as client:
        try:
            health = await client.get(f"{API_URL}/health", timeout=5.0)
            if health.status_code == 200:
                health_data = health.json()
                print(f"{Colors.GREEN}✓ API is running{Colors.END}")
                print(f"  Claude AI: {'✓ Configured' if health_data.get('claude_ai_configured') else '✗ Not configured (using fallback)'}")
                print(f"  Browserbase: {'✓ Configured' if health_data.get('browserbase_configured') else '✗ Not configured'}")
            else:
                print(f"{Colors.RED}✗ API health check failed: HTTP {health.status_code}{Colors.END}")
                return {}
        except Exception as e:
            print(f"{Colors.RED}✗ Cannot connect to API at {API_URL}{Colors.END}")
            print(f"  Error: {e}")
            print(f"\n  Make sure the server is running: python main.py")
            return {}
    
    # Load test data
    test_data = load_test_data(category)
    
    if not test_data:
        print(f"{Colors.RED}No test data found{Colors.END}")
        return {}
    
    print(f"\n{Colors.BOLD}Loading test data...{Colors.END}")
    for cat, data in test_data.items():
        count = len(data.get("emails", []))
        if limit:
            count = min(count, limit)
        print(f"  {cat}: {count} emails")
    
    # Run tests
    all_results = {}
    
    async with httpx.AsyncClient() as client:
        for cat, data in test_data.items():
            emails = data.get("emails", [])
            expected = data.get("expected_result", {})
            
            if limit:
                emails = emails[:limit]
            
            print(f"\n{Colors.BOLD}Testing {cat.upper()} emails ({len(emails)} samples)...{Colors.END}")
            
            results = []
            for i, email in enumerate(emails):
                result = await test_email(client, email, expected)
                results.append(result)
                
                # Progress indicator
                status = f"{Colors.GREEN}✓{Colors.END}" if result.passed else f"{Colors.RED}✗{Colors.END}"
                
                if verbose:
                    print(f"  [{i+1}/{len(emails)}] {status} {result.email_id}")
                    print(f"       Expected: {result.expected_threat} (is_phishing={result.expected_is_phishing})")
                    print(f"       Actual:   {result.actual_threat} (is_phishing={result.actual_is_phishing}, confidence={result.confidence:.2f})")
                    if not result.passed:
                        print(f"       {Colors.YELLOW}Reason: {result.reason[:80]}...{Colors.END}" if len(result.reason) > 80 else f"       {Colors.YELLOW}Reason: {result.reason}{Colors.END}")
                else:
                    # Simple progress bar
                    progress = (i + 1) / len(emails)
                    bar_width = 30
                    filled = int(bar_width * progress)
                    bar = "█" * filled + "░" * (bar_width - filled)
                    print(f"\r  Progress: [{bar}] {i+1}/{len(emails)} {status}", end="", flush=True)
            
            if not verbose:
                print()  # New line after progress bar
            
            all_results[cat] = results
    
    return all_results


def print_summary(results: dict):
    """Print test summary with statistics"""
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}                       TEST SUMMARY{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}═══════════════════════════════════════════════════════════════{Colors.END}\n")
    
    total_passed = 0
    total_failed = 0
    total_time = 0
    
    category_colors = {
        "phishing": Colors.RED,
        "tech_support": Colors.YELLOW,
        "scareware": Colors.PURPLE,
        "benign": Colors.GREEN
    }
    
    for cat, cat_results in results.items():
        passed = sum(1 for r in cat_results if r.passed)
        failed = len(cat_results) - passed
        total_passed += passed
        total_failed += failed
        
        avg_time = sum(r.response_time_ms for r in cat_results) / len(cat_results) if cat_results else 0
        total_time += sum(r.response_time_ms for r in cat_results)
        
        accuracy = (passed / len(cat_results) * 100) if cat_results else 0
        
        color = category_colors.get(cat, Colors.WHITE)
        status_color = Colors.GREEN if accuracy >= 80 else (Colors.YELLOW if accuracy >= 60 else Colors.RED)
        
        print(f"{color}{Colors.BOLD}{cat.upper()}{Colors.END}")
        print(f"  Passed: {Colors.GREEN}{passed}{Colors.END} | Failed: {Colors.RED}{failed}{Colors.END}")
        print(f"  Accuracy: {status_color}{accuracy:.1f}%{Colors.END}")
        print(f"  Avg Response Time: {avg_time:.0f}ms")
        
        # Show failed cases
        if failed > 0:
            print(f"  {Colors.YELLOW}Failed cases:{Colors.END}")
            for r in cat_results:
                if not r.passed:
                    print(f"    - {r.email_id}: expected {r.expected_threat}, got {r.actual_threat}")
        print()
    
    # Overall summary
    total = total_passed + total_failed
    overall_accuracy = (total_passed / total * 100) if total else 0
    avg_response_time = total_time / total if total else 0
    
    print(f"{Colors.BOLD}{'─' * 63}{Colors.END}")
    print(f"{Colors.BOLD}OVERALL RESULTS{Colors.END}")
    print(f"  Total Tests: {total}")
    print(f"  Passed: {Colors.GREEN}{total_passed}{Colors.END} | Failed: {Colors.RED}{total_failed}{Colors.END}")
    
    status_color = Colors.GREEN if overall_accuracy >= 80 else (Colors.YELLOW if overall_accuracy >= 60 else Colors.RED)
    print(f"  Overall Accuracy: {status_color}{Colors.BOLD}{overall_accuracy:.1f}%{Colors.END}")
    print(f"  Total Time: {total_time/1000:.1f}s | Avg per Email: {avg_response_time:.0f}ms")
    print()


def export_results(results: dict, output_file: str = "test_results.json"):
    """Export detailed results to JSON file"""
    export_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {},
        "details": {}
    }
    
    for cat, cat_results in results.items():
        passed = sum(1 for r in cat_results if r.passed)
        export_data["summary"][cat] = {
            "total": len(cat_results),
            "passed": passed,
            "failed": len(cat_results) - passed,
            "accuracy": (passed / len(cat_results) * 100) if cat_results else 0
        }
        
        export_data["details"][cat] = [
            {
                "email_id": r.email_id,
                "expected_threat": r.expected_threat,
                "actual_threat": r.actual_threat,
                "expected_is_phishing": r.expected_is_phishing,
                "actual_is_phishing": r.actual_is_phishing,
                "confidence": r.confidence,
                "reason": r.reason,
                "passed": r.passed,
                "response_time_ms": r.response_time_ms
            }
            for r in cat_results
        ]
    
    output_path = Path(__file__).parent / output_file
    with open(output_path, "w") as f:
        json.dump(export_data, f, indent=2)
    
    print(f"{Colors.CYAN}Results exported to: {output_path}{Colors.END}")


def main():
    parser = argparse.ArgumentParser(
        description="Test Phishing Shield API with sample emails",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_emails.py                     # Test all categories
  python test_emails.py -c phishing         # Test only phishing emails
  python test_emails.py -l 10               # Test 10 emails per category
  python test_emails.py -v                  # Verbose output
  python test_emails.py -e                  # Export results to JSON
        """
    )
    
    parser.add_argument(
        "-c", "--category",
        choices=["phishing", "tech_support", "scareware", "benign"],
        help="Test specific category only"
    )
    
    parser.add_argument(
        "-l", "--limit",
        type=int,
        help="Limit number of emails per category"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed output for each test"
    )
    
    parser.add_argument(
        "-e", "--export",
        action="store_true",
        help="Export results to JSON file"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="test_results.json",
        help="Output file for results (default: test_results.json)"
    )
    
    args = parser.parse_args()
    
    # Run tests
    results = asyncio.run(run_tests(
        category=args.category,
        limit=args.limit,
        verbose=args.verbose
    ))
    
    if results:
        print_summary(results)
        
        if args.export:
            export_results(results, args.output)


if __name__ == "__main__":
    main()
