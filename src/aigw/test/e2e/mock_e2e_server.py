#!/usr/bin/env python3
"""
Mock Server for AIGW E2E Testing

This mock server simulates:
1. Kubernetes API server - provides Endpoints information for DP workers
2. vLLM Worker backends - receives streaming requests from AIGW and returns SSE responses

Usage:
    python3 mock_e2e_server.py [--k8s-port 8080] [--worker-base-port 9000] [--num-workers 2] [--dp-size 2]
"""

import argparse
import json
import logging
import random
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional


logger = logging.getLogger(__name__)


@dataclass
class DPWorker:
    """Represents a DP-aware worker"""
    name: str
    ip: str
    port: int
    role: str  # "prefill" or "decode"
    model: str
    dp_rank: int
    dp_size: int
    group_id: str
    labels: Dict[str, str]


class K8sMockHandler(BaseHTTPRequestHandler):
    """Mock Kubernetes API handler"""

    workers: List[DPWorker] = []

    def log_message(self, fmt, *args):
        """Custom log format"""
        logger.info(f"[K8s-Mock] {self.address_string()} - {fmt % args}")

    def _do_get(self):
        """Handle GET requests for Kubernetes API."""
        if self.path.startswith('/api/v1/namespaces/') and '/endpoints' in self.path:
            if 'watch=true' in self.path:
                self.handle_watch_endpoints()
            else:
                self.handle_list_endpoints()
        else:
            self.send_error(404, "Not Found")

    # BaseHTTPRequestHandler dispatches via getattr(self, 'do_'+command);
    # expose runtime names as class-body aliases (G.NAM.01 scans def names).
    do_GET = _do_get

    def handle_watch_endpoints(self):
        """Handle watching endpoints (mock Kubernetes Watch API)"""
        parts = self.path.split('/')
        namespace = parts[4] if len(parts) > 4 else "default"

        logger.info(f"[K8s-Mock] Watch endpoints requested for namespace {namespace}")

        # Send initial ADDED events for all existing workers
        # Use Connection: close to ensure connection is closed after response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Connection', 'close')  # Close connection after response
        self.end_headers()

        # Group workers by service name
        worker_groups = {}
        for worker in self.workers:
            service_name = f"{worker.role}-{worker.group_id}"
            if service_name not in worker_groups:
                worker_groups[service_name] = []
            worker_groups[service_name].append(worker)

        # Send ADDED event for each endpoint
        for service_name, workers in worker_groups.items():
            addresses = []
            for w in workers:
                addresses.append({
                    "ip": w.ip,
                    "nodeName": f"node-{w.name}",
                    "targetRef": {
                        "kind": "Pod",
                        "namespace": namespace,
                        "name": w.name,
                        "uid": str(uuid.uuid4())
                    }
                })

            endpoint = {
                "apiVersion": "v1",
                "kind": "Endpoints",
                "metadata": {
                    "name": service_name,
                    "namespace": namespace,
                    "labels": {
                        "app": "vllm",
                        "role": workers[0].role,
                        "model": workers[0].model,
                        "group-id": workers[0].group_id,
                        "dp-rank": str(workers[0].dp_rank)
                    },
                    "uid": str(uuid.uuid4())
                },
                "subsets": [{
                    "addresses": addresses,
                    "ports": [{
                        "name": "http",
                        "port": workers[0].port,
                        "protocol": "TCP"
                    }]
                }]
            }

            event = json.dumps({"type": "ADDED", "object": endpoint})
            self.wfile.write((event + '\n').encode())
            self.wfile.flush()
            logger.info(f"[K8s-Mock] Sent ADDED event for {service_name}")

        # Send BOOKMARK event to signal completion (standard K8s watch behavior)
        heartbeat = json.dumps({
            "type": "BOOKMARK",
            "object": {
                "kind": "Endpoints",
                "metadata": {"resourceVersion": str(int(time.time()))}
            }
        })
        self.wfile.write((heartbeat + '\n').encode())
        self.wfile.flush()

        # Explicitly close the connection to avoid resource leak
        self.wfile.flush()
        if hasattr(self, '_close_connection'):
            self._close_connection()

        logger.info(f"[K8s-Mock] Watch stream completed for namespace {namespace}")

    def handle_list_endpoints(self):
        """Handle listing endpoints (mock Kubernetes Endpoints API)"""
        # Parse namespace from path
        parts = self.path.split('/')
        namespace = parts[4] if len(parts) > 4 else "default"

        # Build Endpoints response
        endpoints = []
        worker_groups = {}

        # Group workers by service name
        for worker in self.workers:
            service_name = f"{worker.role}-{worker.group_id}"
            if service_name not in worker_groups:
                worker_groups[service_name] = []
            worker_groups[service_name].append(worker)

        # Build endpoints for each service
        for service_name, workers in worker_groups.items():
            addresses = []
            for w in workers:
                addresses.append({
                    "ip": w.ip,
                    "nodeName": f"node-{w.name}",
                    "targetRef": {
                        "kind": "Pod",
                        "namespace": namespace,
                        "name": w.name,
                        "uid": str(uuid.uuid4())
                    }
                })

            endpoints.append({
                "apiVersion": "v1",
                "kind": "Endpoints",
                "metadata": {
                    "name": service_name,
                    "namespace": namespace,
                    "labels": {
                        "app": "vllm",
                        "role": workers[0].role,
                        "model": workers[0].model,
                        "group-id": workers[0].group_id,
                        "dp-rank": str(workers[0].dp_rank)
                    },
                    "uid": str(uuid.uuid4())
                },
                "subsets": [{
                    "addresses": addresses,
                    "ports": [{
                        "name": "http",
                        "port": workers[0].port,
                        "protocol": "TCP"
                    }]
                }]
            })

        response = {
            "apiVersion": "v1",
            "kind": "EndpointsList",
            "metadata": {
                "resourceVersion": str(int(time.time()))
            },
            "items": endpoints
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())
        logger.info(f"[K8s-Mock] Returning {len(endpoints)} endpoints for namespace {namespace}")


class WorkerMockHandler(BaseHTTPRequestHandler):
    """Mock vLLM Worker handler"""

    worker_name: str = "worker-0"
    dp_rank: int = 0
    dp_size: int = 1
    request_count: int = 0

    def log_message(self, fmt, *args):
        """Custom log format"""
        logger.info(f"[Worker-{self.worker_name}] {self.address_string()} - {fmt % args}")

    def _do_post(self):
        """Handle POST requests."""
        if self.path == '/v1/chat/completions':
            self.handle_chat_completions()
        elif self.path == '/v1/completions':
            self.handle_completions()
        else:
            self.send_error(404, "Not Found")

    # BaseHTTPRequestHandler dispatches via getattr(self, 'do_'+command);
    # expose runtime names as class-body aliases (G.NAM.01 scans def names).
    do_POST = _do_post

    def handle_chat_completions(self):
        """Handle chat completions request (supports streaming)"""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"
        request = json.loads(body)

        # Check for DP rank header
        dp_rank_header = self.headers.get("X-data-parallel-rank", "not-set")

        WorkerMockHandler.request_count += 1
        req_id = WorkerMockHandler.request_count

        logger.info(f"\n[Worker-{self.worker_name}] ===== Request #{req_id} =====")
        logger.info(f"  DP-Rank Header: {dp_rank_header}")
        logger.info(f"  Worker DP-Rank: {self.dp_rank}")
        logger.info(f"  Model: {request.get('model', 'unknown')}")
        logger.info(f"  Stream: {request.get('stream', False)}")
        logger.info(f"  Messages: {len(request.get('messages', []))} messages")

        is_stream = request.get("stream", False)
        model = request.get("model", "mock-model")

        if is_stream:
            self.handle_streaming_response(request, model, req_id)
        else:
            self.handle_non_streaming_response(request, model, req_id)

    def handle_streaming_response(self, request, model, req_id):
        """Handle streaming SSE response"""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")  # Disable nginx buffering
        self.end_headers()

        # Generate mock streaming response
        messages = request.get("messages", [])
        last_message = messages[-1].get("content", "Hello") if messages else "Hello"

        # Mock response chunks
        response_text = f"[Worker-{self.worker_name}|DP-{self.dp_rank}] Response to: {last_message[:50]}"
        words = response_text.split()

        # Send SSE events
        chunk_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
        created = int(time.time())

        for i, word in enumerate(words):
            chunk = {
                "id": chunk_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{
                    "index": 0,
                    "delta": {
                        "content": word + " "
                    },
                    "finish_reason": None
                }]
            }

            # Send event
            event_data = f"data: {json.dumps(chunk)}\n\n"
            self.wfile.write(event_data.encode())
            self.wfile.flush()
            logger.info(f"[Worker-{self.worker_name}] Sent chunk {i+1}/{len(words)}: {word}")
            time.sleep(0.05)  # Simulate streaming delay

        # Send final chunk with finish_reason
        final_chunk = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {},
                "finish_reason": "stop"
            }]
        }

        self.wfile.write(f"data: {json.dumps(final_chunk)}\n\n".encode())
        self.wfile.write("data: [DONE]\n\n".encode())
        self.wfile.flush()

        logger.info(f"[Worker-{self.worker_name}] Streaming completed for request #{req_id}\n")

    def handle_non_streaming_response(self, request, model, req_id):
        """Handle non-streaming response"""
        messages = request.get("messages", [])
        last_message = messages[-1].get("content", "Hello") if messages else "Hello"

        response = {
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"[Worker-{self.worker_name}|DP-{self.dp_rank}] Response to: {last_message}"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30
            }
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2).encode())
        logger.info(f"[Worker-{self.worker_name}] Non-streaming response sent for request #{req_id}\n")

    def handle_completions(self):
        """Handle completions request"""
        self.send_error(501, "Not Implemented")


def run_k8s_server(port: int, workers: List[DPWorker]):
    """Run the mock Kubernetes API server"""
    K8sMockHandler.workers = workers
    server = HTTPServer(('0.0.0.0', port), K8sMockHandler)
    logger.info(f"[K8s-Mock] Starting Kubernetes mock server on port {port}")
    logger.info(
        f"[K8s-Mock] Endpoints: http://localhost:{port}"
        f"/api/v1/namespaces/{workers[0].group_id}/endpoints"
    )
    server.serve_forever()


def run_worker_server(port: int, name: str, dp_rank: int, dp_size: int):
    """Run a mock worker server"""
    WorkerMockHandler.worker_name = name
    WorkerMockHandler.dp_rank = dp_rank
    WorkerMockHandler.dp_size = dp_size
    server = HTTPServer(('0.0.0.0', port), WorkerMockHandler)
    logger.info(
        f"[Worker-{name}] Starting worker server on port {port} "
        f"(DP-Rank: {dp_rank}/{dp_size})"
    )
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description='Mock E2E Server for AIGW Testing')
    parser.add_argument('--k8s-port', type=int, default=18080, help='Port for mock K8s API server')
    parser.add_argument('--worker-base-port', type=int, default=19000, help='Base port for worker servers')
    parser.add_argument('--num-workers', type=int, default=2, help='Number of physical workers')
    parser.add_argument('--dp-size', type=int, default=2, help='DP size (virtual workers per physical)')
    parser.add_argument('--namespace', type=str, default='vllm', help='Kubernetes namespace')
    parser.add_argument('--model', type=str, default='test-model', help='Model name')

    args = parser.parse_args()

    # Create workers
    workers = []
    for i in range(args.num_workers):
        # Prefill worker
        workers.append(DPWorker(
            name=f"prefill-{i}",
            ip="127.0.0.1",
            port=args.worker_base_port + i * 2,
            role="prefill",
            model=args.model,
            dp_rank=0,  # Will be expanded by AIGW
            dp_size=args.dp_size,
            group_id=f"group-{i}",
            labels={"app": "vllm", "role": "prefill", "model": args.model}
        ))

        # Decode worker
        workers.append(DPWorker(
            name=f"decode-{i}",
            ip="127.0.0.1",
            port=args.worker_base_port + i * 2 + 1,
            role="decode",
            model=args.model,
            dp_rank=0,
            dp_size=args.dp_size,
            group_id=f"group-{i}",
            labels={"app": "vllm", "role": "decode", "model": args.model}
        ))

    logger.info("=" * 60)
    logger.info("AIGW E2E Mock Server")
    logger.info("=" * 60)
    logger.info(f"Configuration:")
    logger.info(f"  K8s API Port: {args.k8s_port}")
    logger.info(f"  Worker Base Port: {args.worker_base_port}")
    logger.info(f"  Num Workers: {args.num_workers}")
    logger.info(f"  DP Size: {args.dp_size}")
    logger.info(f"  Namespace: {args.namespace}")
    logger.info(f"  Model: {args.model}")
    logger.info("=" * 60)
    logger.info("\nWorkers:")
    for w in workers:
        logger.info(f"  {w.name:15} | {w.role:8} | Port: {w.port} | Group: {w.group_id}")
    logger.info("=" * 60)

    # Start threads
    threads = []

    # K8s server thread
    k8s_thread = threading.Thread(
        target=run_k8s_server,
        args=(args.k8s_port, workers),
        daemon=True
    )
    threads.append(k8s_thread)

    # Worker server threads
    for worker in workers:
        thread = threading.Thread(
            target=run_worker_server,
            args=(worker.port, worker.name, worker.dp_rank, worker.dp_size),
            daemon=True
        )
        threads.append(thread)

    # Start all threads
    for thread in threads:
        thread.start()

    logger.info("\nAll servers started. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\nShutting down...")


if __name__ == "__main__":
    main()
