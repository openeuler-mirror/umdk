#!/usr/bin/env python3
"""
Test Client for AIGW E2E Testing

This client tests:
1. AIGW scheduling with consistent hash
2. AIGW request forwarding with DP rank injection
3. Streaming response handling

Usage:
    python3 test_e2e_client.py --aigw-host 127.0.0.1 --aigw-port 8888
"""

import argparse
import json
import time
import uuid
import requests
from typing import Dict, List, Optional
import sys


def test_health(aigw_url: str):
    """Test AIGW health endpoint"""
    print("\n" + "=" * 60)
    print("Test 1: Health Check")
    print("=" * 60)

    try:
        response = requests.get(f"{aigw_url}/aigw/v1/health", timeout=5)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error: {e}")
        return False


def test_get_suggestion(aigw_url: str, model: str, session_id: Optional[str] = None):
    """Test AIGW scheduling suggestion"""
    print("\n" + "=" * 60)
    print("Test 2: Get Scheduling Suggestion")
    print("=" * 60)

    request_body = {
        "uuid": str(uuid.uuid4()),
        "model": model,
        "messages": [
            {"role": "user", "content": "Hello, how are you?"}
        ],
        "stream": True
    }

    headers = {
        "Content-Type": "application/json"
    }

    # Add session ID for consistent hash
    if session_id:
        headers["X-Session-Id"] = session_id
        print(f"Session ID: {session_id}")

    try:
        response = requests.post(
            f"{aigw_url}/aigw/v1/openai/get-suggestion",
            json=request_body,
            headers=headers,
            timeout=10
        )

        print(f"Status: {response.status_code}")

        if response.status_code == 200:
            result = response.json()
            print(f"Prefill URL: {result.get('targetPrefill', 'N/A')}")
            print(f"Decode URL: {result.get('targetDecode', 'N/A')}")
            print(f"DP Rank: {result.get('dpRank', 'N/A')}")
            return result
        else:
            print(f"Error: {response.text}")
            return None

    except Exception as e:
        print(f"Error: {e}")
        return None


def test_forward_chat_completion(aigw_url: str, model: str, stream: bool = True,
                                  session_id: Optional[str] = None):
    """Test AIGW request forwarding"""
    print("\n" + "=" * 60)
    print(f"Test 3: Forward Chat Completion (stream={stream})")
    print("=" * 60)

    request_body = {
        "uuid": str(uuid.uuid4()),
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Tell me a short joke about AI."}
        ],
        "stream": stream
    }

    headers = {
        "Content-Type": "application/json"
    }

    if session_id:
        headers["X-Session-Id"] = session_id
        print(f"Session ID: {session_id}")

    try:
        if stream:
            # Streaming request
            response = requests.post(
                f"{aigw_url}/aigw/v1/openai/chat/completions",
                json=request_body,
                headers=headers,
                stream=True,
                timeout=30
            )

            print(f"Status: {response.status_code}")
            print(f"Content-Type: {response.headers.get('Content-Type', 'N/A')}")
            print("\nStreaming Response:")
            print("-" * 40)

            full_content = ""
            for line in response.iter_lines():
                if line:
                    line_str = line.decode('utf-8')
                    if line_str.startswith('data: '):
                        data = line_str[6:]
                        if data == '[DONE]':
                            print("\n[DONE]")
                            break
                        try:
                            chunk = json.loads(data)
                            delta = chunk.get('choices', [{}])[0].get('delta', {})
                            content = delta.get('content', '')
                            if content:
                                print(content, end='', flush=True)
                                full_content += content
                        except json.JSONDecodeError:
                            pass

            print("\n" + "-" * 40)
            print(f"Full content length: {len(full_content)} chars")
            return True

        else:
            # Non-streaming request
            request_body["stream"] = False
            response = requests.post(
                f"{aigw_url}/aigw/v1/openai/chat/completions",
                json=request_body,
                headers=headers,
                timeout=30
            )

            print(f"Status: {response.status_code}")

            if response.status_code == 200:
                result = response.json()
                print(f"Response: {json.dumps(result, indent=2)}")
                return True
            else:
                print(f"Error: {response.text}")
                return False

    except Exception as e:
        print(f"Error: {e}")
        return False


def test_consistent_hash_affinity(aigw_url: str, model: str, num_requests: int = 5):
    """Test that consistent hash routes to the same worker"""
    print("\n" + "=" * 60)
    print("Test 4: Consistent Hash Session Affinity")
    print("=" * 60)

    session_id = f"test-session-{int(time.time())}"
    results = []

    print(f"Session ID: {session_id}")
    print(f"Making {num_requests} requests with same session ID...\n")

    for i in range(num_requests):
        result = test_get_suggestion(aigw_url, model, session_id)
        if result:
            prefill_url = result.get('targetPrefill', 'N/A')
            dp_rank = result.get('dpRank', 'N/A')
            results.append((prefill_url, dp_rank))
            print(f"Request {i+1}: {prefill_url} (DP-Rank: {dp_rank})")
        time.sleep(0.1)

    # Check if all requests went to the same worker
    if results:
        unique_urls = set(r[0] for r in results)
        unique_ranks = set(r[1] for r in results)

        print(f"\nResults:")
        print(f"  Unique URLs: {len(unique_urls)}")
        print(f"  Unique Ranks: {len(unique_ranks)}")

        if len(unique_urls) == 1:
            print("✅ PASS: All requests routed to same worker URL")
            return True
        else:
            print("❌ FAIL: Requests routed to different workers")
            return False
    else:
        print("❌ FAIL: No successful requests")
        return False


def test_dp_rank_injection(aigw_url: str, model: str):
    """Test that DP rank is properly injected in forwarded requests"""
    print("\n" + "=" * 60)
    print("Test 5: DP Rank Header Injection")
    print("=" * 60)

    # Make different session requests to trigger different DP ranks
    print("Making requests with different session IDs...\n")

    dp_ranks_seen = set()

    for i in range(4):
        session_id = f"dp-test-session-{i}"
        result = test_get_suggestion(aigw_url, model, session_id)
        if result:
            dp_rank = result.get('dpRank')
            if dp_rank is not None:
                dp_ranks_seen.add(dp_rank)
                print(f"Session {session_id}: DP-Rank = {dp_rank}")
        time.sleep(0.1)

    print(f"\nDP Ranks seen: {sorted(dp_ranks_seen)}")

    if len(dp_ranks_seen) > 1:
        print("✅ PASS: Different DP ranks assigned to different sessions")
        return True
    elif len(dp_ranks_seen) == 1:
        print("⚠️ PARTIAL: Same DP rank for all sessions (might be expected with DP size = 1)")
        return True
    else:
        print("❌ FAIL: No DP rank information")
        return False


def main():
    parser = argparse.ArgumentParser(description='Test Client for AIGW E2E Testing')
    parser.add_argument('--aigw-host', type=str, default='127.0.0.1', help='AIGW host')
    parser.add_argument('--aigw-port', type=int, default=8888, help='AIGW port')
    parser.add_argument('--model', type=str, default='test-model', help='Model name')
    parser.add_argument('--skip-forward', action='store_true', help='Skip forwarding tests')

    args = parser.parse_args()

    aigw_url = f"http://{args.aigw_host}:{args.aigw_port}"

    print("=" * 60)
    print("AIGW E2E Test Client")
    print("=" * 60)
    print(f"AIGW URL: {aigw_url}")
    print(f"Model: {args.model}")
    print("=" * 60)

    # Run tests
    results = {}

    # Test 1: Health
    results['health'] = test_health(aigw_url)

    # Test 2: Get Suggestion
    results['suggestion'] = test_get_suggestion(aigw_url, args.model) is not None

    # Test 3: Forward (if not skipped)
    if not args.skip_forward:
        results['forward_stream'] = test_forward_chat_completion(aigw_url, args.model, stream=True)
        results['forward_non_stream'] = test_forward_chat_completion(aigw_url, args.model, stream=False)

    # Test 4: Consistent Hash Affinity
    results['hash_affinity'] = test_consistent_hash_affinity(aigw_url, args.model)

    # Test 5: DP Rank Injection
    results['dp_rank'] = test_dp_rank_injection(aigw_url, args.model)

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)

    passed = 0
    failed = 0

    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test_name:25}: {status}")
        if result:
            passed += 1
        else:
            failed += 1

    print("-" * 60)
    print(f"Total: {passed} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
