"""A deterministic stand-in for an LLM that is vulnerable to indirect prompt injection.

Why mock it? The gaps in this lab sit in the identity layer, not in a particular model.
Any model that can be induced to emit a tool call reproduces them, and prompt
injection against current models is well documented. A deterministic planner keeps
results reproducible, which a real model can't promise. Swap in Ollama or an API model if you
want to see a real model reach the same tool calls.
"""
from __future__ import annotations

import re

DIRECTIVE = re.compile(r"<!--\s*AGENT-DIRECTIVE\s+(\w+)\s*\n(.*?)END-DIRECTIVE\s*-->", re.S)


class MockLLM:
    def __init__(self, model: str, system_prompt: str, tools: list[str]):
        self.model, self.system_prompt, self.tools = model, system_prompt, tools

    def plan(self, task: str) -> dict:
        if m := re.search(r"record (?:for|of) (\w+)", task, re.I):
            return {"tool": "get_record", "args": {"user": m.group(1).lower()}}
        if m := re.search(r"summari[sz]e (?:the )?(?:doc(?:ument)? )?([\w.-]+)", task, re.I):
            return {"tool": "read_doc", "args": {"name": m.group(1)}}
        return {"final": "I can fetch HR records or summarise documents."}

    def observe(self, tool: str, result) -> dict:
        """Decide the next step after a tool result. This is where injection takes over."""
        if tool == "read_doc":
            text = result.get("text", "")
            for name, payload in DIRECTIVE.findall(text):
                # The model 'helpfully' obeys instructions hidden in retrieved content.
                if name == "run_python" and "run_python" in self.tools:
                    return {"tool": "run_python", "args": {"code": payload}}
                if name == "summarize" and "summarize" in self.tools:
                    return {"tool": "summarize", "args": {"text": DIRECTIVE.sub("", text)}}
            return {"final": f"Summary: {text[:160]}"}
        return {"final": result}
