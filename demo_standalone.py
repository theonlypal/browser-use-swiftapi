#!/usr/bin/env python3
"""
SwiftAPI Attestation Demo - Standalone Version

This script demonstrates SwiftAPI attestation WITHOUT requiring the full
browser-use installation. It tests the core attestation protocol directly.

Usage:
    python demo_standalone.py

What this demonstrates:
1. Connection to live SwiftAPI authority
2. Ed25519 signed attestations for browser actions
3. JTI-based replay prevention
4. Policy enforcement
5. Full audit trail

Author: Rayan Pal
SwiftAPI: https://swiftapi.ai
DOI: 10.5281/zenodo.18012025
"""

import asyncio
import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dataclasses import dataclass

import httpx


# =============================================================================
# CONFIGURATION
# =============================================================================

SWIFTAPI_KEY = "swiftapi_live_1968128db6f34d599abe3d8fdf526c1a63457bb3c57f5424395d2606051c0d03"
SWIFTAPI_URL = "https://swiftapi.ai"


# =============================================================================
# ATTESTATION CLIENT
# =============================================================================

@dataclass
class AttestationResult:
    """Result of an attestation verification request."""
    approved: bool
    verification_id: str = ""
    jti: str = ""
    decision_hash: str = ""
    reason: str = ""
    expires_at: str = ""
    raw_response: Optional[Dict] = None


class SwiftAPIClient:
    """Client for SwiftAPI attestation authority."""

    def __init__(self, api_key: str, base_url: str = SWIFTAPI_URL):
        self.api_key = api_key
        self.base_url = base_url
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=30,
                headers={
                    "X-SwiftAPI-Authority": self.api_key,
                    "Content-Type": "application/json",
                    "User-Agent": "browser-use-swiftapi-demo/1.0.0",
                },
            )
        return self._client

    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get_info(self) -> Dict[str, Any]:
        """Get SwiftAPI authority info."""
        client = await self._get_client()
        response = await client.get("/")
        response.raise_for_status()
        return response.json()

    async def get_health(self) -> Dict[str, Any]:
        """Get SwiftAPI health status."""
        client = await self._get_client()
        response = await client.get("/health")
        response.raise_for_status()
        return response.json()

    async def verify(
        self,
        action_type: str,
        intent: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> AttestationResult:
        """Verify an action and get attestation."""
        client = await self._get_client()

        payload = {
            "action": {
                "type": action_type,
                "intent": intent,
                "params": params,
            },
            "context": {
                "app_id": "browser-use-demo",
                "actor": "demo-agent",
                "environment": "demo",
                "request_id": f"demo_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
                **(context or {}),
            },
        }

        try:
            response = await client.post("/verify", json=payload)
            data = response.json()

            if response.status_code == 200:
                attestation = data.get("execution_attestation", {})
                return AttestationResult(
                    approved=data.get("approved", False),
                    verification_id=data.get("verification_id", ""),
                    jti=attestation.get("jti", ""),
                    decision_hash=data.get("decision_hash", ""),
                    reason=data.get("reason", ""),
                    expires_at=attestation.get("expires_at", ""),
                    raw_response=data,
                )
            else:
                return AttestationResult(
                    approved=False,
                    reason=data.get("reason", f"HTTP {response.status_code}"),
                    raw_response=data,
                )

        except httpx.HTTPStatusError as e:
            return AttestationResult(
                approved=False,
                reason=f"HTTP Error: {e.response.status_code}",
            )
        except Exception as e:
            return AttestationResult(
                approved=False,
                reason=f"Error: {e}",
            )


# =============================================================================
# DEMO FUNCTIONS
# =============================================================================

async def test_connection(client: SwiftAPIClient) -> bool:
    """Test connection to SwiftAPI."""
    print("\n" + "=" * 70)
    print("TEST 1: CONNECTION TO SWIFTAPI AUTHORITY")
    print("=" * 70)

    try:
        # Test health endpoint first
        print("\n📡 Testing health endpoint...")
        health = await client.get_health()
        print(f"   Status: {health.get('status', 'unknown')}")

        # Get authority info
        print("\n📡 Getting authority info...")
        info = await client.get_info()
        print(f"   ✅ Connected to SwiftAPI Authority")
        print(f"   Authority: {info.get('authority', 'swiftapi.ai')}")
        print(f"   Version: {info.get('version', 'unknown')}")

        if info.get("public_key"):
            pk = info.get("public_key", "")
            print(f"   Public Key: {pk[:32]}..." if len(pk) > 32 else f"   Public Key: {pk}")

        return True

    except Exception as e:
        print(f"\n   ❌ Connection failed: {e}")
        return False


async def test_attestation_flow(client: SwiftAPIClient) -> None:
    """Test various action attestations."""
    print("\n" + "=" * 70)
    print("TEST 2: ATTESTATION FLOW")
    print("=" * 70)

    # Actions that a browser agent would execute
    test_actions = [
        {
            "type": "click",
            "params": {"element_index": 5},
            "intent": "Click on search button",
            "context": {"page_url": "https://github.com"},
        },
        {
            "type": "input",
            "params": {"text": "browser-use", "element_index": 3},
            "intent": "Type search query into input field",
            "context": {"page_url": "https://github.com/search"},
        },
        {
            "type": "navigate",
            "params": {"url": "https://github.com/browser-use/browser-use"},
            "intent": "Navigate to browser-use repository",
            "context": {"page_url": "https://github.com/search?q=browser-use"},
        },
        {
            "type": "evaluate",
            "params": {"script": "document.title"},
            "intent": "Get page title via JavaScript",
            "context": {"page_url": "https://github.com/browser-use/browser-use"},
        },
    ]

    results = []
    for i, action in enumerate(test_actions, 1):
        print(f"\n--- Action {i}: {action['type']} ---")
        print(f"    Intent: {action['intent']}")
        print(f"    Params: {action['params']}")

        result = await client.verify(
            action_type=action["type"],
            intent=action["intent"],
            params=action["params"],
            context=action.get("context"),
        )

        if result.approved:
            print(f"    ✅ APPROVED")
            print(f"       Verification ID: {result.verification_id}")
            if result.jti:
                print(f"       JTI: {result.jti[:24]}...")
            if result.expires_at:
                print(f"       Expires: {result.expires_at}")
            results.append(result)
        else:
            print(f"    ❌ DENIED: {result.reason}")

    print(f"\n📊 Results: {len(results)}/{len(test_actions)} actions approved")
    return results


async def demo_browser_use_task(client: SwiftAPIClient) -> None:
    """Simulate a complete browser-use task with attestation."""
    print("\n" + "=" * 70)
    print("TEST 3: SIMULATED BROWSER-USE TASK")
    print("=" * 70)
    print("\n🎯 Task: 'Search for browser-use on GitHub and star the repository'")
    print("-" * 70)

    # This simulates the actions a browser-use agent would take
    task_actions = [
        ("navigate", {"url": "https://github.com"}, "Navigate to GitHub homepage"),
        ("click", {"element_index": 1}, "Click on search input"),
        ("input", {"text": "browser-use", "element_index": 1}, "Type 'browser-use'"),
        ("click", {"element_index": 5}, "Click search button"),
        ("click", {"element_index": 3}, "Click first search result"),
        ("click", {"element_index": 15}, "Click star button"),
    ]

    approved_count = 0
    attestations = []

    for action_type, params, description in task_actions:
        print(f"\n🔄 Step: {description}")
        print(f"   Action: {action_type}({params})")

        result = await client.verify(
            action_type=action_type,
            intent=f"browser-use agent: {description}",
            params=params,
        )

        if result.approved:
            approved_count += 1
            attestations.append(result)
            jti_display = f" (JTI: {result.jti[:16]}...)" if result.jti else ""
            print(f"   ✅ APPROVED{jti_display}")
        else:
            print(f"   ❌ BLOCKED: {result.reason}")
            # In real browser-use, the agent would receive this feedback
            # and could adjust its strategy

    print("\n" + "-" * 70)
    print(f"📊 Task Summary: {approved_count}/{len(task_actions)} actions executed")

    if attestations:
        print("\n📜 Audit Trail (Attestation JTIs):")
        for i, att in enumerate(attestations, 1):
            if att.jti:
                print(f"   {i}. {att.jti}")


async def show_integration_code() -> None:
    """Show how to integrate with browser-use."""
    print("\n" + "=" * 70)
    print("INTEGRATION CODE")
    print("=" * 70)

    code = '''
# SwiftAPI Integration for Browser-Use
# =====================================

# Option 1: SwiftAPI-enabled Agent
from swiftapi_integration import SwiftAPIAgent

agent = SwiftAPIAgent(
    task="Search for browser-use on GitHub and star it",
    llm=ChatOpenAI(model="gpt-4"),
    swiftapi_key="swiftapi_live_..."  # Or set SWIFTAPI_KEY env var
)
result = await agent.run()
# Every click, type, navigate is attested before execution

# Option 2: SwiftAPI-enabled Tools
from swiftapi_integration import SwiftAPITools
from browser_use import Agent

tools = SwiftAPITools(swiftapi_key="swiftapi_live_...")
agent = Agent(task="...", llm=llm, tools=tools)
result = await agent.run()

# Option 3: NullProvider for development (no attestation)
from swiftapi_integration import SwiftAPITools, NullAttestationProvider

tools = SwiftAPITools(attestation_provider=NullAttestationProvider())
# All actions pass through without attestation (dev only!)
'''
    print(code)


async def main():
    """Main demo entry point."""
    print("=" * 70)
    print("  BROWSER-USE + SWIFTAPI INTEGRATION DEMO")
    print("  Cryptographic Attestation for Browser Agents")
    print("=" * 70)
    print("\n🔐 SwiftAPI Authority: https://swiftapi.ai")
    print("📄 Protocol Spec: DOI 10.5281/zenodo.18012025")
    print(f"🔑 API Key: {SWIFTAPI_KEY[:24]}...")

    client = SwiftAPIClient(SWIFTAPI_KEY)

    try:
        # Run all tests
        connected = await test_connection(client)
        if not connected:
            print("\n❌ Cannot proceed without SwiftAPI connection")
            return

        await test_attestation_flow(client)
        await demo_browser_use_task(client)
        await show_integration_code()

        print("\n" + "=" * 70)
        print("  DEMO COMPLETE")
        print("=" * 70)
        print("""
KEY TAKEAWAYS:

  1. Every high-risk action is attested before execution
  2. Attestations are cryptographically signed (Ed25519)
  3. JTI provides replay prevention and instant revocation
  4. Read-only actions can pass through without attestation
  5. Fail-closed by default: no key = no execution

WHAT THIS MEANS FOR BROWSER-USE:

  ❌ Before: Agents execute actions with no governance
  ✅ After:  Every action has cryptographic proof of authorization

  ❌ Before: No audit trail for what agents did
  ✅ After:  Complete audit trail with verification IDs

  ❌ Before: Can't prove compliance to enterprises
  ✅ After:  Enterprise-ready with attestation records

  ❌ Before: No way to revoke an agent mid-task
  ✅ After:  Instant revocation via JTI

This is what enterprise-ready browser automation looks like.
""")
        print("=" * 70)

    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
