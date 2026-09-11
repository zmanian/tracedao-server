import json
import io
import time
import http.server
import threading
import subprocess
import tempfile
import pathlib
import os
import sys
import unittest
from qualify import inspect_response, read_measured, ProcessSamples


class QualificationParser(unittest.TestCase):
    def frame(self, streaming=False):
        text = "é"
        tokens = [{"bytes": [value], "logprob": -1.25,
                   "top_logprobs": [{"bytes": [value], "logprob": -1.25}]}
                  for value in text.encode()]
        return {"id": "fixture", "choices": [{"index": 0, "finish_reason": "stop",
                             "delta" if streaming else "message": {"content": text},
                             "logprobs": {"content": tokens}}]}

    def test_json_and_sse_preserve_split_utf8_bytes(self):
        frame = self.frame()
        result = inspect_response(json.dumps(frame).encode(), False)
        self.assertEqual(result["tokens"], 2)
        self.assertNotIn("bytes", result)
        frame = self.frame(True)
        wire = ("data: " + json.dumps(frame) + "\n\ndata: [DONE]\n\n").encode()
        self.assertEqual(result, inspect_response(wire, True))
        with self.assertRaises(ValueError):
            inspect_response(wire.replace(b"data: [DONE]\n\n", b""), True)

    def test_stream_timing_reports_content_chunks_without_persisting_content(self):
        frame = self.frame(True)
        wire = ("data: " + json.dumps(frame) + "\n\ndata: [DONE]\n\n").encode()
        raw, timing = read_measured(io.BytesIO(wire), True, time.monotonic())
        self.assertEqual(raw, wire)
        self.assertEqual(timing["content_chunks"], 1)
        self.assertGreaterEqual(timing["ttft_ms"], 0)
        self.assertIsNone(timing["inter_content_chunk_mean_ms"])
        self.assertNotIn("é", json.dumps(timing))
        self.assertIsNone(ProcessSamples(None).metrics()["process_cpu_seconds"])

    def test_missing_or_mismatched_probabilities_are_not_support(self):
        for mutate in [lambda c: c.pop("logprobs"),
                       lambda c: c["message"].update(content="different"),
                       lambda c: c["logprobs"]["content"][0].update(logprob=float("nan"))]:
            frame = self.frame()
            mutate(frame["choices"][0])
            with self.assertRaises(ValueError):
                inspect_response(json.dumps(frame).encode(), False)


class QualificationMatrix(unittest.TestCase):
    def test_loopback_matrix_records_timing_without_response_content(self):
        class Provider(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                def record(text):
                    value = {"bytes": list(text.encode()), "logprob": -1.25}
                    return dict(value, top_logprobs=[value] * body.get("top_logprobs", 0))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream" if body["stream"] else "application/json")
                self.end_headers()
                if body["stream"]:
                    for i, text in enumerate(["blue", " sky."]):
                        frame = {"id":"fixture", "choices":[{"index":0,"finish_reason":"stop" if i else None,"delta":{"content":text},"logprobs":{"content":[record(text)]}}]}
                        self.wfile.write(("data: " + json.dumps(frame) + "\n\n").encode())
                        self.wfile.flush()
                        time.sleep(0.01)
                    self.wfile.write(b"data: [DONE]\n\n")
                else:
                    frame = {"id":"fixture", "choices":[{"index":0,"finish_reason":"stop","message":{"content":"blue sky."},"logprobs":{"content":[record("blue"),record(" sky.")]}}]}
                    self.wfile.write(json.dumps(frame).encode())
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as root:
                output = pathlib.Path(root) / "report.json"
                env = dict(os.environ, TOKEN_PROBE_API_KEY="synthetic-fixture-token")
                result = subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name("qualify.py")),
                    "--endpoint", f"http://127.0.0.1:{server.server_port}/chat/completions", "--backend", "fixture",
                    "--model", "fixture", "--matrix", "--output", str(output)], env=env, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 0)
                report = output.read_text()
                self.assertNotIn("blue", report)
                self.assertNotIn("synthetic-fixture-token", report)
                probes = json.loads(report)["probes"]
                self.assertEqual(len(probes), 8)
                self.assertEqual({p["requested_top_k"] for p in probes}, {None, 0, 5, 20})
                for probe in probes:
                    if probe["streaming"]:
                        self.assertEqual(probe["content_chunks"], 2)
                        self.assertGreaterEqual(probe["ttft_ms"], 0)
                        self.assertGreater(probe["inter_content_chunk_mean_ms"], 0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
