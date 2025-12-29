SwiftAPI Attestation for browser-use

This adds execution governance to browser-use. Every browser action (click, type, navigate) gets cryptographically attested before it runs. No attestation, no execution.

Why this exists:
- AI agents clicking around the web without oversight is a liability nightmare
- Enterprises need audit trails and kill switches
- "Trust but verify" doesn't work when the agent is autonomous

What it does:
- Wraps browser-use Tools/Agent with attestation layer
- Calls SwiftAPI /verify before any high-risk action
- Blocks execution if policy denies or service is unreachable (fail-closed)
- Passes through read-only actions (screenshot, extract) without attestation

Installation:

    pip install browser-use httpx

Usage:

    from swiftapi_integration import SwiftAPIAgent
    from langchain_openai import ChatOpenAI

    agent = SwiftAPIAgent(
        task="Find the pricing page",
        llm=ChatOpenAI(model="gpt-4o"),
        swiftapi_key="swiftapi_live_..."  # or set SWIFTAPI_KEY env var
    )
    await agent.run()

Or wrap existing tools:

    from swiftapi_integration import SwiftAPITools

    tools = SwiftAPITools(swiftapi_key="swiftapi_live_...")
    # pass to Agent as controller=tools

Configuration:

    SwiftAPIConfig(
        api_key="...",              # required
        base_url="https://swiftapi.ai",
        app_id="browser-use",
        actor="browser-use-agent",
        timeout=10,
        fail_open=False,            # DO NOT set True in production
        verbose=True,
    )

Files:
- config.py: Configuration dataclass
- attestation.py: HTTP client and attestation providers
- tools.py: SwiftAPITools wrapping browser-use Tools
- agent.py: SwiftAPIAgent wrapping browser-use Agent
- demo_standalone.py: Working example that hits live SwiftAPI

PR to browser-use: https://github.com/browser-use/browser-use/pull/3824

Get a key: https://swiftapi.ai

License: MIT
