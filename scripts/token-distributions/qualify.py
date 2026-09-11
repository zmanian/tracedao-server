#!/usr/bin/env python3
"""Synthetic Chat probability probe. Writes metadata only; never response text.

A successful probe establishes wire support for this exact model and endpoint
at this time, not probability semantics, attestation, or production readiness.
"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import math
import os
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

LIMIT = 8 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("redirect-refused")


def inspect_response(raw, streaming):
    if streaming:
        frames = []
        done = False
        for line in raw.decode("utf-8").splitlines():
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                done = True
            elif data:
                if done:
                    raise ValueError("data-after-done")
                frames.append(json.loads(data))
        if not done:
            raise ValueError("incomplete-stream")
    else:
        frames = [json.loads(raw)]
    text, records, finished = [], [], False
    response_id = None
    for frame in frames:
        current_id = frame.get("id")
        if not isinstance(current_id, str) or not current_id or len(current_id) > 256:
            raise ValueError("response-id-unavailable")
        if response_id is not None and response_id != current_id:
            raise ValueError("response-id-changed")
        response_id = current_id
        if len(frame.get("choices", [])) > 1:
            raise ValueError("unsupported-choice")
        for choice in frame.get("choices", []):
            if choice.get("index") != 0:
                raise ValueError("unsupported-choice")
            message = choice.get("delta" if streaming else "message", {})
            if message.get("tool_calls") or message.get("reasoning_content"):
                raise ValueError("unsupported-content")
            text.append(message.get("content") or "")
            records.extend((choice.get("logprobs") or {}).get("content") or [])
            finished |= choice.get("finish_reason") == "stop"
    if not finished or not records:
        raise ValueError("probabilities-unavailable")
    chosen = bytearray()
    alternative_counts = []
    for record in records:
        alternatives = record.get("top_logprobs") or []
        alternative_counts.append(len(alternatives))
        for token in [record] + alternatives:
            raw_bytes = token.get("bytes")
            probability = token.get("logprob")
            if not isinstance(raw_bytes, list) or not raw_bytes:
                raise ValueError("token-bytes-unavailable")
            if any(type(b) is not int or not 0 <= b <= 255 for b in raw_bytes):
                raise ValueError("invalid-token-bytes")
            if type(probability) not in (float, int) or not math.isfinite(probability) or probability > 0:
                raise ValueError("probability-semantics-unsupported")
        chosen.extend(record["bytes"])
    if bytes(chosen) != "".join(text).encode("utf-8"):
        raise ValueError("byte-reconstruction-mismatch")
    return {"tokens": len(records), "minimum_alternatives": min(alternative_counts),
            "maximum_alternatives": max(alternative_counts), "exact_bytes": True}


class ProcessSamples:
    """Optional local-process RSS/CPU samples; never read command lines or env."""
    def __init__(self, pid):
        self.pid, self.samples, self.stop = pid, [], threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
    def run(self):
        while not self.stop.is_set():
            try:
                fields = subprocess.check_output(["ps", "-p", str(self.pid), "-o", "rss=", "-o", "time="], stderr=subprocess.DEVNULL, timeout=2).decode().split()
                day, _, clock = fields[1].rpartition("-")
                parts = (clock or fields[1]).split(":")
                seconds = 0.0
                for part in parts:
                    seconds = seconds * 60 + float(part)
                seconds += int(day or 0) * 86400
                self.samples.append((int(fields[0]) * 1024, seconds))
            except (OSError, ValueError, IndexError, subprocess.SubprocessError):
                pass
            self.stop.wait(0.05)
    def __enter__(self):
        if self.pid: self.thread.start()
        return self
    def __exit__(self, *_):
        self.stop.set()
        if self.pid: self.thread.join(timeout=3)
    def metrics(self):
        return {"process_samples":len(self.samples),
                "process_peak_rss_bytes":max((s[0] for s in self.samples), default=None),
                "process_cpu_seconds":round(max(0, self.samples[-1][1]-self.samples[0][1]), 4) if len(self.samples)>1 else None}


def read_measured(response, streaming, started):
    raw = bytearray()
    arrivals = []
    if not streaming:
        raw.extend(response.read(LIMIT+1))
    else:
        while len(raw) <= LIMIT:
            line = response.readline(min(65536, LIMIT+1-len(raw)))
            if not line: break
            raw.extend(line)
            if line.startswith(b"data:") and line[5:].strip() != b"[DONE]":
                frame = json.loads(line[5:])
                if any(c.get("delta", {}).get("content") for c in frame.get("choices", [])):
                    arrivals.append(time.monotonic())
    if len(raw)>LIMIT: raise ValueError("response-too-large")
    gaps = [1000*(b-a) for a,b in zip(arrivals, arrivals[1:])]
    return bytes(raw), {"ttft_ms":round(1000*(arrivals[0]-started), 3) if arrivals else None,
        "content_chunks":len(arrivals), "inter_content_chunk_mean_ms":statistics.mean(gaps) if gaps else None,
        "inter_content_chunk_max_ms":max(gaps, default=None)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, help="Exact Chat Completions HTTPS endpoint")
    parser.add_argument("--model", required=True)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--token-env", default="TOKEN_PROBE_API_KEY")
    parser.add_argument("--top-k", type=int, choices=range(21), default=20)
    parser.add_argument("--matrix", action="store_true", help="Compare baseline, chosen-only, K=5 and K=20 in JSON and SSE")
    parser.add_argument("--repeats", type=int, choices=range(1, 21), default=1)
    parser.add_argument("--process-pid", type=int, help="Optional local proxy PID for RSS and CPU sampling")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.process_pid is not None and args.process_pid <= 0:
        parser.error("Process PID must be positive")
    endpoint = urllib.parse.urlsplit(args.endpoint)
    try:
        local = ipaddress.ip_address(endpoint.hostname or "").is_loopback
    except ValueError:
        local = False
    if endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or not (
        endpoint.scheme == "https" or (endpoint.scheme == "http" and local)
    ):
        parser.error("Use HTTPS or a literal loopback address without URL credentials or query parameters")
    token = os.environ.get(args.token_env)
    if not token:
        parser.error("The named token environment variable is unset")
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    result = {"version": 1, "backend": args.backend, "model": args.model,
              "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "endpoint_digest": hashlib.sha256(args.endpoint.encode()).hexdigest(),
              "semantics": "unknown", "conditioning": "unknown", "probes": []}
    cases = [(k, stream) for k in ([None, 0, 5, 20] if args.matrix else [None, args.top_k]) for stream in [False, True]]
    for top_k, streaming in cases * args.repeats:
        probabilities = top_k is not None
        body = {"model": args.model, "messages": [{"role": "user", "content": "Reply exactly: blue sky."}],
                "max_tokens": 32, "stream": streaming}
        if probabilities:
            body.update(logprobs=True, top_logprobs=top_k)
        probe = {"requested_probabilities": probabilities, "streaming": streaming,
                 "requested_top_k": top_k}
        started = time.monotonic()
        try:
            request = urllib.request.Request(args.endpoint, data=json.dumps(body).encode(),
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
            with ProcessSamples(args.process_pid) as samples:
                with opener.open(request, timeout=60) as response:
                    raw, timing = read_measured(response, streaming, started)
                    probe["http_status"] = response.status
                probe.update(timing)
            probe.update(samples.metrics())
            if len(raw) > LIMIT:
                raise ValueError("response-too-large")
            probe["response_bytes"] = len(raw)
            if probabilities:
                probe.update(inspect_response(raw, streaming))
            probe["status"] = "supported" if probabilities else "baseline"
        except urllib.error.HTTPError as error:
            probe.update(status="unavailable", http_status=error.code)
        except (ValueError, KeyError, TypeError, OSError):
            probe["status"] = "unavailable"
        probe["elapsed_ms"] = round(1000 * (time.monotonic() - started), 2)
        result["probes"].append(probe)
    # Never persist token bytes, probabilities, credentials, or provider errors.
    with open(args.output, "x", encoding="utf-8") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    return 0 if all(p["status"] != "unavailable" for p in result["probes"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
