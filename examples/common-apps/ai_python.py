"""One explicit, non-streaming AI call using an ordinary provider SDK.

The only provider credential in this process is the public replacement dummy.
Real API keys remain in Catchplate. The proxy independently enforces the scope.
"""
from __future__ import annotations

import argparse
import importlib.util
from importlib.metadata import version
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
from uuid import UUID

PINS = {"openai": "3.31.0", "anthropic": "1.15.0", "google-genai": "2.31.0",
    "httpx2": "2.13.1", "httpx": "0.28.1"}
OPERATIONS = {"openai": ("responses_text_v1", "https://api.openai.com/v1/responses"),
    "anthropic": ("messages_text_v1", "https://api.anthropic.com/v1/messages"),
    "gemini": ("generate_text_v1", "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"),
    "openrouter": ("chat_text_v1", "https://openrouter.ai/api/v1/chat/completions")}
FAILURE = "AI request failed. Check Catchplate's audit log; no request was automatically retried."


def validate_scope(config, prompt):
    provider = config.get("app_preset")
    if provider not in OPERATIONS or type(prompt) is not str or not 1 <= len(prompt) <= 4096:
        raise ValueError("Choose a supported AI permission and a prompt of 1 to 4096 characters")
    scope = config.get("scope")
    if type(scope) is not dict or set(scope) != {"model", "max_output_tokens"}:
        raise ValueError("AI permission scope required")
    pattern = r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}" if provider == "gemini" else r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}"
    if provider == "openrouter":
        pattern = r"(?!openrouter/)[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
    if (type(scope["model"]) is not str or re.fullmatch(pattern, scope["model"]) is None
            or type(scope["max_output_tokens"]) is not int or not 16 <= scope["max_output_tokens"] <= 4096):
        raise ValueError("AI model or output-token limit refused")
    operation, url = OPERATIONS[provider]
    if (config.get("app_operation") != operation or config.get("upstream_url") != url.format(**scope)
            or config.get("methods") != ["POST"]):
        raise ValueError("AI target differs from the selected permission")
    return provider, scope


def _context(ca_file=None):
    # SSLContext does not consume SSL_CERT_FILE, SSL_CERT_DIR or SSLKEYLOGFILE.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if ca_file is None:
        context.load_default_certs()
    else:
        with open(ca_file, "rb") as stream:
            pem = stream.read(65537)
        if not 0 < len(pem) <= 65536 or b"PRIVATE KEY" in pem:
            raise ValueError("Invalid public CA file")
        context.load_verify_locations(cadata=pem.decode("ascii"))
    return context


def http_client(config, provider):
    """Separate verified outer-proxy and intercepted-destination TLS roots."""
    if provider == "gemini":
        import httpx as http
    else:
        import httpx2 as http
    proxy = http.Proxy(config["proxy_url"],
        auth=(config["proxy_username"], config["proxy_password"]),
        ssl_context=_context(config.get("proxy_ca_file")))
    transport = http.HTTPTransport(proxy=proxy, verify=_context(config["ca_file"]),
        trust_env=False, retries=0)
    return http.Client(transport=transport, trust_env=False, follow_redirects=False,
        timeout=30.0, headers={"accept-encoding": "identity"})


def infer(config, prompt, *, client):
    """Keep a validated Catchplate review path without exposing SDK error bodies."""
    try:
        return _infer(config, prompt, client=client)
    except Exception as error:
        response = getattr(error, "response", None)
        if getattr(response, "status_code", None) != 428:
            raise
        raw = getattr(response, "content", None)
        if not isinstance(raw, bytes) or not 0 < len(raw) <= 65536:
            raise
        try:
            value = json.loads(raw)
            payload = value["payload"]
            identifier = value["approval_id"]
            path = "/approvals/" + identifier
            valid = (type(value) is dict and type(payload) is dict
                and type(identifier) is str and str(UUID(identifier)) == identifier
                and value.get("allowed") is False and value.get("action") == "approval_required"
                and value.get("status_code") == 428 and value.get("approval_url") == path
                and payload.get("error") == "host_trusted_approval_required"
                and payload.get("approval_status") == "pending"
                and payload.get("approval_id") == identifier and payload.get("approval_url") == path
                and payload.get("retry_semantics") == "explicit_identical_request_after_approval")
        except (ValueError, TypeError, KeyError):
            raise error from None
        if not valid:
            raise
        return {"status": "approval_required", "http_status": 428, "approval_path": path,
            "instruction": "Open this path on the Catchplate console and approve the request, then explicitly rerun the identical request with unchanged prompt and configuration. No retry was sent."}


def _infer(config, prompt, *, client):
    """Supported SDK methods; injected client is also the offline-test seam."""
    provider, scope = validate_scope(config, prompt)
    token = "catchplate-" + provider + "-placeholder-v1"
    model, maximum = scope["model"], scope["max_output_tokens"]
    if provider in {"openai", "openrouter"}:
        from openai import OpenAI
        base = "https://api.openai.com/v1" if provider == "openai" else "https://openrouter.ai/api/v1"
        with OpenAI(api_key=token, base_url=base, max_retries=0, timeout=30.0,
                http_client=client) as sdk:
            if provider == "openai":
                response = sdk.responses.create(model=model, input=prompt,
                    max_output_tokens=maximum, stream=False, store=False)
                return {"provider": provider, "status": response.status, "text": response.output_text}
            response = sdk.chat.completions.create(model=model,
                messages=[{"role": "user", "content": prompt}], max_tokens=maximum, stream=False)
            if not response.choices:
                raise ValueError("No model response")
            return {"provider": provider, "status": response.choices[0].finish_reason,
                "text": response.choices[0].message.content}
    if provider == "anthropic":
        from anthropic import Anthropic
        # The SDK probes profile discovery even with an explicit key. An empty
        # private directory avoids ambient profiles and works without a Unix home.
        with tempfile.TemporaryDirectory(prefix="catchplate-anthropic-") as profile_dir:
            previous = os.environ.get("ANTHROPIC_CONFIG_DIR")
            os.environ["ANTHROPIC_CONFIG_DIR"] = profile_dir
            try:
                with Anthropic(api_key=token, base_url="https://api.anthropic.com", max_retries=0,
                        timeout=30.0, http_client=client) as sdk:
                    response = sdk.messages.create(model=model,
                        messages=[{"role": "user", "content": prompt}], max_tokens=maximum, stream=False)
                    return {"provider": provider, "status": response.stop_reason,
                        "text": "".join(block.text for block in response.content if block.type == "text")}
            finally:
                if previous is None:
                    os.environ.pop("ANTHROPIC_CONFIG_DIR", None)
                else:
                    os.environ["ANTHROPIC_CONFIG_DIR"] = previous
    from google import genai
    from google.genai import types
    options = types.HttpOptions(api_version="v1beta", timeout=30000, httpx_client=client,
        retry_options=types.HttpRetryOptions(attempts=1))
    with genai.Client(api_key=token, vertexai=False, http_options=options) as sdk:
        response = sdk.models.generate_content(model=model, contents=prompt,
            config=types.GenerateContentConfig(max_output_tokens=maximum))
        if not response.candidates:
            raise ValueError("No model response")
        return {"provider": provider, "status": str(response.candidates[0].finish_reason),
            "text": response.text}


def load_configuration(path):
    # Import our adjacent data-only loader; never execute a downloaded recipe.
    spec = importlib.util.spec_from_file_location("common_apps_request", Path(__file__).with_name("request.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.load_configuration(path)


def launch(config, prompt):
    validate_scope(config, prompt)
    if any(version(package) != pin for package, pin in PINS.items()):
        raise ValueError("Install requirements-ai.txt in a dedicated Python 3.12 environment")
    # SDKs also read provider-specific headers, organization and base URL env vars.
    # Start clean instead of leaking ambient provider keys or trusting overrides.
    message = json.dumps({"configuration": config, "prompt": prompt}).encode("utf-8")
    if len(message) > 128 * 1024:
        raise ValueError("Configuration too large")
    completed = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--child"],
        input=message, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, timeout=60, check=False)
    if completed.returncode or len(completed.stdout) > 1024 * 1024:
        raise ValueError(FAILURE)
    return json.loads(completed.stdout)


def main():
    if sys.argv[1:] == ["--child"]:
        # No debug, ambient proxy/credentials, ADC, TLS key log or API base override.
        if set(os.environ) - {"LC_CTYPE"}:
            raise ValueError("Clean child environment required")
        payload = json.loads(sys.stdin.buffer.read(128 * 1024 + 1))
        config, prompt = payload["configuration"], payload["prompt"]
        provider, _ = validate_scope(config, prompt)
        with http_client(config, provider) as client:
            result = infer(config, prompt, client=client)
        print(json.dumps(result))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Private configuration downloaded from Catchplate")
    parser.add_argument("--prompt", required=True, help="Text to send to the selected provider")
    parser.add_argument("--send", action="store_true", help="Explicitly send one potentially billable request")
    args = parser.parse_args()
    if not args.send:
        parser.error("Add --send to explicitly make one potentially billable request")
    result = launch(load_configuration(args.config), args.prompt)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(FAILURE, file=sys.stderr)
        raise SystemExit(1)
