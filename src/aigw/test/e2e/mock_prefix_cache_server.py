"""
Mock Prefix Cache E2E Test Server.

Simulates:
- K8s API server (endpoint watch, instance discovery) - port 8000
- vLLM workers with KV cache - ports 19000-19003
- Render service (tokenization) - port 18080

Architecture:
  K8s Mock (port 8000):
    - /api/v1/endpoints -> watch endpoint events
    - Returns ADDED events for workers

  Worker Nodes (ports 19000-19003):
    - /v1/chat/completions -> chat completion
    - /subscribe-event -> KV cache event subscription
    - AIGW health check endpoint

  Render Server (port 18080):
    - /v1/chat/completions/render -> tokenization
    - Deterministic token IDs for same messages

  Prefix Cache Test:
    - Workers advertise KV events endpoint info
    - Render service provides tokenization via port 18080
"""

import hashlib
import json
import logging
import os
import signal
import socket
import subprocess
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs


# Threading HTTP Server to handle multiple concurrent connections
class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """HTTP Server with thread-per-request handling."""
    daemon_threads = True  # Auto-kill threads when main process exits

try:
    import zmq
    HAS_ZMQ = True
except ImportError:
    HAS_ZMQ = False
    print("[WARN] pyzmq not installed. KV event publishing disabled. Install with: pip install pyzmq")

try:
    import msgpack
    HAS_MSGPACK = True
except ImportError:
    HAS_MSGPACK = False
    print("[WARN] msgpack not installed. KV events will use JSON (may not work). Install with: pip install msgpack")

# Configure logging to file
LOG_FILE = "/tmp/mock_server.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="w"),  # 'w' mode clears file on startup
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("mock_server")

WORKER_PORTS = [19000, 19001, 19002, 19003]
MOCK_K8S_PORT = 8000       # K8s API mock server
MOCK_RENDER_PORT = 18080   # Render service mock server
AIGW_PORT = 8701
AIGW_HOST = "127.0.0.1"

# Simulated worker instances
WORKERS = {}
for port in WORKER_PORTS:
    WORKERS[port] = {
        "name": f"worker-{port}",
        "ip": "127.0.0.1",
        "port": port,
        "url": f"http://127.0.0.1:{port}",
        "model": "prefix-cache-test-model",
        "kv_events_port": port + 10000,
        "kv_events_ip": "127.0.0.1",
        "render_port": port,
    }


# ============================================================
# K8s Mock Server
# ============================================================

class K8sMockHandler(BaseHTTPRequestHandler):
    """Mock K8s API server for endpoint watch."""

    def do_GET(self):
        parsed = urlparse(self.path)
        logger.info(f"[K8S] GET {self.path} from {self.client_address}")
        if parsed.path.endswith("/endpoints") and "watch" in parse_qs(parsed.query):
            self._handle_watch()
        elif parsed.path.endswith("/endpoints"):
            self._handle_list()
        else:
            self._return_json(404, {"error": "not found"})

    def _handle_list(self):
        """Handle listing all endpoints."""
        endpoints = {
            "kind": "EndpointsList",
            "items": []
        }
        for port, worker in WORKERS.items():
            ep = {
                "kind": "Endpoints",
                "metadata": {
                    "name": worker["name"],
                    "annotations": {
                        "modelName": worker["model"],
                        "instanceName": worker["name"],
                    }
                },
                "subsets": [{
                    "addresses": [{"ip": worker["ip"]}],
                    "ports": [
                        {"name": "http", "port": worker["port"], "protocol": "TCP"},
                        {"name": "kv-events", "port": worker["kv_events_port"], "protocol": "TCP"},
                    ]
                }]
            }
            endpoints["items"].append(ep)
        self._return_json(200, endpoints)

    def _handle_watch(self):
        """Handle watch endpoint events - sends ADDED events for all workers."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()

        for port, worker in WORKERS.items():
            event = {
                "type": "ADDED",
                "object": {
                    "kind": "Endpoints",
                    "metadata": {
                        "name": worker["name"],
                        "annotations": {
                            "modelName": worker["model"],
                            "instanceName": worker["name"],
                        }
                    },
                    "subsets": [{
                        "addresses": [{"ip": worker["ip"]}],
                        "ports": [
                            {"name": "http", "port": worker["port"], "protocol": "TCP"},
                            {"name": "kv-events", "port": worker["kv_events_port"], "protocol": "TCP"},
                        ]
                    }]
                }
            }
            chunk = json.dumps(event) + "\n"
            self.wfile.write(f"{len(chunk):x}\r\n".encode())
            self.wfile.write(chunk.encode())
            self.wfile.write(b"\r\n")
            time.sleep(0.1)

        self.wfile.write(b"0\r\n\r\n")

    def do_POST(self):
        """Handle POST requests (if needed)."""
        self._return_json(200, {"status": "ok"})

    def _return_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


# ============================================================
# Render Service Mock Server
# ============================================================

class RenderMockHandler(BaseHTTPRequestHandler):
    """Mock vLLM render service - provides deterministic tokenization."""

    def do_GET(self):
        if self.path == "/health" or self.path == "/aigw/health":
            logger.info(f"[RENDER_HEALTH] Request from {self.client_address}")
            self._return_json(200, {"status": "healthy"})
        else:
            self._return_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            self._return_json(400, {"error": "invalid json"})
            return

        if parsed.path.endswith("/render"):
            self._handle_render(data)
        elif parsed.path.endswith("/chat/completions"):
            self._handle_chat(data)
        else:
            self._return_json(404, {"error": "not found"})

    def _handle_render(self, data):
        """Simulate vLLM render service - tokenize messages.

        Returns deterministic token IDs based on message content.
        Uses WORD-BASED tokenization that preserves prefix information.
        Algorithm MUST match generate_token_ids() exactly.
        """
        model = data.get("model", "unknown")
        messages = data.get("messages", [])

        logger.info(f"[RENDER] Request: model={model}, messages={messages}")

        # Build prompt from message contents
        prompt = " ".join(m.get("content", "") for m in messages).strip()
        logger.info(f"[RENDER] prompt=\"{prompt}\"")

        # Use the same generate_token_ids function for consistency
        token_ids = generate_token_ids(prompt, min_tokens=16)
        prompt_len = len(token_ids)

        response = {
            "prompt": prompt,
            "token_ids": token_ids,
            "prompt_len": prompt_len,
            "model_config": {
                "max_model_len": 4096
            }
        }

        logger.info(f"[RENDER] Response: token_ids={token_ids}, prompt_len={prompt_len}")

        # Return SSE format as vLLM does
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")  # Close connection to signal end of response
        self.end_headers()

        sse_data = f"data: {json.dumps(response)}\n\n"
        self.wfile.write(sse_data.encode())
        self.wfile.flush()

    def _handle_chat(self, data):
        """Simulate chat completion."""
        model = data.get("model", "unknown")
        messages = data.get("messages", [])
        prompt = " ".join(m.get("content", "") for m in messages)

        logger.info(f"[CHAT] Request: model={model}, messages={messages}")
        
        response = {
            "id": f"chatcmpl-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"Echo from render-server: {prompt}"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": len(prompt),
                "completion_tokens": 10,
                "total_tokens": len(prompt) + 10
            }
        }
        
        logger.info(f"[CHAT] Response: content={response['choices'][0]['message']['content']}")
        self._return_json(200, response)

    def _return_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        pass


# ============================================================
# ZMQ Publisher for KV Events
# ============================================================

class ZMQPublisher:
    """ZMQ Publisher that sends KV events to AIGW on port 5557."""

    def __init__(self, port=5557):
        self.port = port
        self.context = None
        self.socket = None
        self.running = False

    def start(self):
        if not HAS_ZMQ:
            logger.warning("[ZMQ_PUB] pyzmq not available, KV events will not be published")
            return

        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.PUB)
        self.socket.bind(f"tcp://127.0.0.1:{self.port}")
        self.running = True
        logger.info(f"[ZMQ_PUB] Publisher started on tcp://127.0.0.1:{self.port}")

    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()
        if self.context:
            self.context.term()
        logger.info(f"[ZMQ_PUB] Publisher stopped")

    def publish(self, event_type: str, payload: list, model_name: str, instance_name: str):
        """Publish an event to ZMQ.

        AIGW expects a 3-part message:
        1. Topic (empty string if not configured)
        2. Sequence number as 8 bytes big-endian
        3. Data as msgpack: {"Timestamp": int, "Events": [[eventType, eventData, seq]]}

        Args:
            event_type: Event type string (BlockStored, BlockRemoved, AllBlocksCleared)
            payload: Event payload as list
            model_name: Model name
            instance_name: Instance name
        """
        if not self.running or not self.socket:
            logger.warning("[ZMQ_PUB] Publisher not running, dropping event")
            return

        seq = int(time.time() * 1000)

        # Build msgpack batch
        # Go expects: rawEvent = [eventType, blockHashes, parentHash, tokenIDs, blockSize, loraID, seq]
        batch = {
            "Timestamp": seq,
            "Events": [[event_type] + payload + [seq]]
        }

        # Debug: summarize payload by element type and length
        p_summary = [f"{type(p).__name__}[{len(p) if hasattr(p, '__len__') else p}]" for p in payload]
        logger.info(f"[ZMQ_PUB] {event_type} payload=({', '.join(p_summary)})")

        try:
            if HAS_MSGPACK:
                # Encode as msgpack
                data = msgpack.packb(batch, use_bin_type=True)
            else:
                # Fallback to JSON (may not work)
                import json
                data = json.dumps(batch).encode()

            # Send 3-part message: [topic, seq_bytes, data]
            # Use non-empty topic to ensure Go ZMQ SUB socket receives messages
            topic = b"kv"
            seq_bytes = seq.to_bytes(8, byteorder='big')

            self.socket.send_multipart([topic, seq_bytes, data])
            logger.info(f"[ZMQ_PUB] Published {event_type} for {instance_name} (seq={seq})")
        except Exception as e:
            logger.error(f"[ZMQ_PUB] Failed to publish {event_type}: {e}")


# ============================================================
# KV Event Sender
# ============================================================

def generate_token_ids(content: str, min_tokens: int = 16) -> list:
    """Generate token IDs using WORD-BASED tokenization that PRESERVES PREFIX INFORMATION.

    CRITICAL for prefix cache matching: Different texts with shared prefix must produce
    matching tokens for the prefix portion. Padding tokens must be CONTENT-INDEPENDENT.

    Algorithm:
    1. Split content into words
    2. Each word generates 1 token based on its (index, word_content)
    3. Padding tokens are generated using FIXED content (not word-count dependent)
    4. Same prefix words → same prefix tokens → prefix cache match works!

    Example (block_size=2):
      Stored: "Where is the capital of France?"
        words: ["Where", "is", "the", "capital", "of", "France?"]
        tokens: [W, is, th, ca, of, Fr]
        blocks: [W,is], [th,ca], [of,Fr], [PAD,PAD], ...

      Query: "Where is the capital of Germany?"
        words: ["Where", "is", "the", "capital", "of", "Germany?"]
        tokens: [W, is, th, ca, of, Ge]
        blocks: [W,is], [th,ca], [of,Ge], [PAD,PAD], ...

      Block 0: [W,is] == [W,is] ✓
      Block 1: [th,ca] == [th,ca] ✓
      Block 2: [of,Fr] != [of,Ge] ✗
      → 2 blocks match, match % = 2/3 = 66% >= 50% → MATCH!

    Args:
        content: Text content to tokenize
        min_tokens: Minimum number of tokens to generate (for padding)
    """
    words = content.strip().split()
    token_ids = []

    # Generate tokens from words (position + content determines token)
    for idx, word in enumerate(words):
        word_data = f"{idx}:{word}".encode()
        word_hash = hashlib.sha256(word_data).digest()
        token_id = int.from_bytes(word_hash[:4], byteorder='big') % 32000
        token_ids.append(token_id)

    # Pad with FIXED content tokens (NOT dependent on word count)
    # This ensures: same padding position → same token, regardless of word count
    while len(token_ids) < min_tokens:
        pad_idx = len(token_ids)
        pad_data = f"__PAD__:{pad_idx}".encode()  # Fixed prefix, only position varies
        pad_hash = hashlib.sha256(pad_data).digest()
        token_id = int.from_bytes(pad_hash[:4], byteorder='big') % 32000
        token_ids.append(token_id)

    logger.info(f"[TOKENIZE] content=\"{content}\", words={len(words)}, tokens={len(token_ids)}")
    for i, tid in enumerate(token_ids):
        word_info = words[i] if i < len(words) else f"PAD"
        logger.info(f"[TOKENIZE] token_id[{i}]={tid} (from word '{word_info}')")
    return token_ids


class KVEventSender:
    """Helper class to send KV events via ZMQPublisher."""

    def __init__(self, worker_id: str, model_name: str, zmq_publisher: ZMQPublisher = None):
        self.worker_id = worker_id
        self.model_name = model_name
        self.zmq_publisher = zmq_publisher
        self.block_size = 1  # Must match Go's blockSize (token count)

    def _generate_block_hashes(self, token_ids: list, num_blocks: int) -> list:
        """Generate block hashes using xxhash (matching Go's hash.go algorithm).
        
        Updated for vLLM v1 format:
          - Tokens are encoded as uint32 big-endian (4 bytes per token)
          - blockSize is token count per block (e.g., 16 tokens per block)
          - bytesPerBlock = blockSize * 4 (16 * 4 = 64 bytes per block)
          - For each block: digest = xxhash.NewWithSeed(seed)
            - Write parentHashBytes (big-endian uint64, matching aibrix)
            - Write blockTokens (bytesPerBlock bytes)
            - Return digest.Sum64()
          - Chain: each block hash becomes parent for next block
        
        Block hashes sent to AIGW are SHA-256 (first 8 bytes big-endian as int64).
        """
        try:
            import xxhash
        except ImportError:
            logger.warning("[BLOCK_HASH] xxhash not installed, using fallback MD5 (WILL NOT MATCH GO!)")
            return [
                int(hashlib.md5(str(t).encode()).hexdigest()[:8], 16)
                for t in token_ids[:num_blocks]
            ]
        
        # Seed must match Go's configuration
        seed = getattr(self, 'seed', 12345678901234567890)

        logger.info(f"[BLOCK_HASH] Generating hashes: seed={seed}, block_size={self.block_size}, "
                    f"num_blocks={num_blocks}, total_tokens={len(token_ids)}, "
                    f"token_ids={token_ids[:8]}...")

        block_hashes = []
        parent_hash = seed

        # Each block contains block_size tokens, each token as 4 bytes big-endian
        bytes_per_block = self.block_size * 4

        for block_idx in range(num_blocks):
            start_idx = block_idx * self.block_size
            end_idx = min(start_idx + self.block_size, len(token_ids))
            
            if start_idx >= len(token_ids):
                break
            
            # Get block tokens and convert to bytes (uint32 big-endian, 4 bytes per token)
            block_tokens = b''.join(
                token_id.to_bytes(4, byteorder='big')
                for token_id in token_ids[start_idx:end_idx]
            )
            
            # Compute xxhash(seed + parent_hash + block_tokens) - exactly matching Go's hash.go
            digest = xxhash.xxh64(seed=seed)
            parent_bytes = parent_hash.to_bytes(8, byteorder='big')  # Big-endian matching Go
            digest.update(parent_bytes)
            digest.update(block_tokens)
            block_hash = digest.intdigest()

            # Store the raw xxhash - Go's hash.go uses xxhash.Sum64() directly
            # No SHA-256 wrapping needed (that was the bug)
            block_hashes.append(block_hash)
            parent_hash = block_hash

            # Detailed debug logging for troubleshooting
            logger.info(f"[BLOCK_HASH] block={block_idx}, seed={seed}, parent_hash={parent_hash}, "
                        f"start_idx={start_idx}, end_idx={end_idx}, "
                        f"tokens={token_ids[start_idx:end_idx]}, "
                        f"block_tokens_hex={block_tokens.hex()}, "
                        f"num_tokens={len(token_ids)}, "
                        f"xxhash={block_hash}")
        
        return block_hashes

    def send_block_stored(self, content: str = "default content", num_blocks: int = 1) -> dict:
        """Build and send a BlockStored event.

        vLLM v1 format:
        Event array: [tag, block_hashes, parent_hash, token_ids (flat list), block_size, lora_id]
        
        Token encoding: Each token is uint32 big-endian (4 bytes).
        Block hashes: SHA-256 (first 8 bytes big-endian as int64).

        Args:
            content: Text content to generate token IDs from
            num_blocks: Number of blocks to generate hashes for

        Returns:
            Event payload dict for logging/debugging
        """
        token_ids = generate_token_ids(content)
        logger.info(f"[KV_EVENT] send_block_stored: content='{content}', num_blocks={num_blocks}, "
                    f"token_ids={token_ids}, block_size={self.block_size}")
        block_hashes = self._generate_block_hashes(token_ids, num_blocks)

        # TokenIDs are sent as flat list (Go's msgpack_decoder will decode as []uint32)
        # and group them by blockSize
        flat_token_ids = list(token_ids)  # msgpack will encode as list[int]

        payload = [
            block_hashes,         # BlockHashes (SHA-256 first 8 bytes as int64)
            None,                 # ParentBlockHash (nil for first block)
            flat_token_ids,       # TokenIDs as flat list (Go decodes as []uint32)
            self.block_size,      # BlockSize (number of tokens per block)
            -1,                   # LoraID
        ]

        if self.zmq_publisher:
            self.zmq_publisher.publish("BlockStored", payload, self.model_name, self.worker_id)

        logger.info(f"[KV_EVENT] BlockStored: worker={self.worker_id}, "
                   f"num_blocks={num_blocks}, token_count={len(token_ids)}, "
                   f"block_size={self.block_size}")

        return {
            "blockHashes": block_hashes,
            "tokenCount": len(token_ids),
        }

    def send_block_removed(self, content: str = "default content", num_blocks: int = 1) -> dict:
        """Build and send a BlockRemoved event (AIBRIX format).

        AIBRIX BlockRemoved payload: [block_hashes]
        - block_hashes: list of int64 hashes (matching engine block hashes)

        Args:
            content: Text content to generate token IDs from
            num_blocks: Number of blocks to remove

        Returns:
            Event payload dict for logging/debugging
        """
        token_ids = generate_token_ids(content)
        block_hashes = self._generate_block_hashes(token_ids, num_blocks)

        # AIBRIX format: payload = [block_hashes]
        payload = [
            block_hashes,          # BlockHashes
        ]

        if self.zmq_publisher:
            self.zmq_publisher.publish("BlockRemoved", payload, self.model_name, self.worker_id)

        logger.info(f"[KV_EVENT] BlockRemoved: worker={self.worker_id}, "
                   f"num_blocks={num_blocks}, block_hashes={block_hashes}")

        return {
            "blockHashes": block_hashes,
        }

    def send_all_blocks_cleared(self) -> dict:
        """Build and send an AllBlocksCleared event."""

        payload = []

        if self.zmq_publisher:
            self.zmq_publisher.publish("AllBlocksCleared", payload, self.model_name, self.worker_id)

        logger.info(f"[KV_EVENT] AllBlocksCleared: worker={self.worker_id}")

        return {}


# ============================================================
# vLLM Worker Mock Server
# ============================================================

class WorkerMockHandler(BaseHTTPRequestHandler):
    """Mock vLLM worker with KV cache events and chat completion."""

    # Simulated prefix cache state: track which instances have which prefixes
    # Maps prefix text -> set of instance URLs
    prefix_cache = {}
    cache_lock = threading.Lock()
    worker_id = None
    kv_event_sender = None  # Will be set by create_worker_handler

    def do_GET(self):
        if self.path == "/health" or self.path == "/aigw/health":
            logger.info(f"[HEALTH] Request from {self.client_address}")
            self._return_json(200, {"status": "healthy", "worker": getattr(self, "worker_id", "unknown")})
        elif self.path == "/healthz":
            logger.info(f"[HEALTHZ] Request from {self.client_address}")
            self._return_json(200, {"status": "ok"})
        elif self.path == "/subscribe-event" or self.path.endswith("/subscribe-event"):
            logger.info(f"[SUBSCRIBE] Client connected: {self.client_address}")
            self._handle_subscribe_event()
        else:
            self._return_json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")  # Strip trailing slashes for robust matching
        logger.info(f"[POST] Request path={path} from {self.client_address}")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length > 0 else "{}"

        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            logger.warning(f"[POST] Invalid JSON: {body}")
            self._return_json(400, {"error": "invalid json"})
            return

        # KV event trigger endpoints
        if path == "/kv-event/block-stored":
            self._handle_kv_event_block_stored(data)
        elif path == "/kv-event/block-removed":
            self._handle_kv_event_block_removed(data)
        elif path == "/kv-event/all-blocks-cleared":
            self._handle_kv_event_all_blocks_cleared(data)
        elif path.endswith("/chat/completions"):
            self._handle_chat(data)
        else:
            logger.warninging(f"[POST] Path not found: {path}")
            self._return_json(404, {"error": "not found"})

    def _handle_subscribe_event(self):
        """Simulate SSE endpoint for instance event subscription.
        
        AIGW connects here to receive real-time instance updates.
        We send periodic heartbeat events to keep the connection alive.
        """
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Transfer-Encoding", "identity")
        self.end_headers()

        try:
            while True:
                # Send metric_event in the format expected by processInsData
                # No "data: " prefix - Go code expects raw JSON with eventType and data fields
                event_data = {
                    "eventType": "metric_event",
                    "data": {
                        "totalKvBlocks": 1024,
                        "freeKvBlocks": 512,
                        "timeToFirstToken": 10.5,
                        "timeBetweenTokens": 2.0,
                        "queueLength": 0,
                        "avgWaitingTime": 3.0
                    }
                }
                event = json.dumps(event_data) + "\n"
                self.wfile.write(event.encode())
                self.wfile.flush()
                # Wait before next heartbeat (5 seconds)
                time.sleep(5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            # Client disconnected
            pass

    def _handle_chat(self, data):
        """Simulate chat completion."""
        model = data.get("model", "unknown")
        messages = data.get("messages", [])
        prompt = " ".join(m.get("content", "") for m in messages)

        logger.info(f"[CHAT] Request: model={model}, messages={messages}")
        
        response = {
            "id": f"chatcmpl-{int(time.time())}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"Echo from worker {getattr(self, 'worker_id', 'unknown')}: {prompt}"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": len(prompt),
                "completion_tokens": 10,
                "total_tokens": len(prompt) + 10
            }
        }

        logger.info(f"[CHAT] Response: content={response['choices'][0]['message']['content']}")
        self._return_json(200, response)

    def _handle_kv_event_block_stored(self, data):
        """Handle POST /kv-event/block-stored.

        Request body:
            {
                "content": "text content for tokenization",
                "num_blocks": 3
            }
        """
        content = data.get("content", "default content")
        num_blocks = data.get("num_blocks", 1)

        sender = getattr(self, 'kv_event_sender', None)
        if sender:
            result = sender.send_block_stored(content, num_blocks)
            self._return_json(200, {"status": "sent", "event": "BlockStored", "detail": result})
        else:
            logger.error(f"[KV_EVENT] sender is None, worker_id={getattr(self, 'worker_id', 'unknown')}, "
                        f"class_kv_event_sender={WorkerMockHandler.kv_event_sender}")
            self._return_json(500, {"error": "KV event sender not initialized"})

    def _handle_kv_event_block_removed(self, data):
        """Handle POST /kv-event/block-removed.

        Request body:
            {
                "content": "text content for tokenization",
                "num_blocks": 2
            }
        """
        content = data.get("content", "default content")
        num_blocks = data.get("num_blocks", 1)

        sender = getattr(self, 'kv_event_sender', None)
        if sender:
            result = sender.send_block_removed(content, num_blocks)
            self._return_json(200, {"status": "sent", "event": "BlockRemoved", "detail": result})
        else:
            self._return_json(500, {"error": "KV event sender not initialized"})

    def _handle_kv_event_all_blocks_cleared(self, data):
        """Handle POST /kv-event/all-blocks-cleared.

        No request body required.
        """
        sender = getattr(self, 'kv_event_sender', None)
        if sender:
            result = sender.send_all_blocks_cleared()
            self._return_json(200, {"status": "sent", "event": "AllBlocksCleared", "detail": result})
        else:
            self._return_json(500, {"error": "KV event sender not initialized"})

    def _return_json(self, status_code, data):
        content = json.dumps(data).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)
        self.wfile.flush()

    def log_message(self, format, *args):
        pass


def create_worker_handler(wid, kv_publisher=None, seed=12345678901234567890, block_size=1):
    """Create a handler class with worker_id set and KV event sender.
    
    Note: Using class attributes instead of __init__ to avoid ThreadingHTTPServer
    initialization order issues.
    """
    sender = KVEventSender(wid, "prefix-cache-test-model", kv_publisher)
    sender.seed = seed
    sender.block_size = block_size

    class Handler(WorkerMockHandler):
        worker_id = wid
        kv_event_sender = sender

    if kv_publisher:
        logger.info(f"[WORKER] KV event sender initialized for {wid} with seed={seed}, block_size={block_size}")
    else:
        logger.warning(f"[WORKER] KV event sender initialized for {wid} WITHOUT publisher (seed={seed}, block_size={block_size})")
    return Handler

# ============================================================
# AIGW Process Management
# ============================================================

def find_aigw_binary():
    """Find the AIGW binary."""
    search_paths = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "build", "output", "aigw"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "build", "aigw"),
    ]
    for p in search_paths:
        path = os.path.abspath(p)
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    return None


def start_aigw(config_path, log_path="/tmp/aigw_pc.log"):
    """Start AIGW process."""
    aigw_bin = find_aigw_binary()
    if not aigw_bin:
        print("[ERROR] AIGW binary not found. Build first with 'sh build.sh'")
        return None

    env = os.environ.copy()
    env["AIGW_PREFIX_CACHE_ENABLED"] = "true"
    env["AIGW_PREFIX_CACHE_BLOCK_SIZE"] = "16"
    env["AIGW_PREFIX_CACHE_MATCH_THRESHOLD"] = "50"
    env["AIGW_PREFIX_CACHE_FALLBACK_STRING_MATCHING"] = "true"
    env["GIN_MODE"] = "release"

    with open(log_path, "w") as f:
        process = subprocess.Popen(
            [aigw_bin, "--config", config_path],
            stdout=f,
            stderr=subprocess.STDOUT,
            env=env,
        )
    return process


# ============================================================
# Server Lifecycle
# ============================================================

class ServerThread(threading.Thread):
    """Thread wrapping an HTTP server."""

    def __init__(self, server, name):
        super().__init__(daemon=True)
        self.server = server
        self.name = name

    def run(self):
        print(f"[INFO] {self.name} starting on {self.server.server_address}")
        logger.info(f"[START] {self.name} starting on {self.server.server_address}")
        self.server.serve_forever()

    def stop(self):
        print(f"[INFO] Stopping {self.name}")
        logger.info(f"[STOP] Stopping {self.name}")
        self.server.shutdown()


def wait_for_port(host, port, timeout=30):
    """Wait for a port to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.5)
    return False


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Prefix Cache E2E Mock Server")
    parser.add_argument("--action", choices=["start", "stop"], default="start")
    parser.add_argument("--pid-file", default="/tmp/mock_pc_server.pid")
    parser.add_argument("--seed", type=int, default=12345678901234567890,
                        help="Seed for xxhash (must match Go's seed, default: 12345678901234567890)")
    parser.add_argument("--block-size", type=int, default=1,
                        help="Block size in tokens (must match Go's blockSize, default: 1)")
    args = parser.parse_args()

    if args.action == "stop":
        if os.path.exists(args.pid_file):
            with open(args.pid_file) as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            os.remove(args.pid_file)
            print("[INFO] Mock server stopped")
        return

    # Log configuration
    logger.info(f"[CONFIG] seed={args.seed}, block_size={args.block_size}")
    print(f"[INFO] Configuration: seed={args.seed}, block_size={args.block_size}")

    # Start K8s mock on port 8000
    k8s_server = ThreadingHTTPServer(("0.0.0.0", MOCK_K8S_PORT), K8sMockHandler)
    k8s_thread = ServerThread(k8s_server, f"K8sMock(:{MOCK_K8S_PORT})")
    k8s_thread.start()
    logger.info(f"[INFO] K8s mock server on port {MOCK_K8S_PORT}")

    # Start Render mock on port 18080
    render_server = ThreadingHTTPServer(("0.0.0.0", MOCK_RENDER_PORT), RenderMockHandler)
    render_thread = ServerThread(render_server, f"RenderMock(:{MOCK_RENDER_PORT})")
    render_thread.start()
    logger.info(f"[INFO] Render mock server on port {MOCK_RENDER_PORT}")

    # Start worker servers (each with its own ZMQ publisher on unique port)
    # This prevents cross-talk: sending event from worker-19000 only notifies AIGW subscribed to that port
    ZMQ_PORT_START = 55570
    worker_threads = []
    worker_publishers = {}
    for i, port in enumerate(WORKER_PORTS):
        zmq_port = ZMQ_PORT_START + i
        publisher = ZMQPublisher(port=zmq_port)
        publisher.start()
        worker_publishers[port] = publisher
        logger.info(f"[INFO] ZMQ publisher for worker-{port} on port {zmq_port}")

        handler = create_worker_handler(f"worker-{port}", publisher, args.seed, args.block_size)
        server = ThreadingHTTPServer(("0.0.0.0", port), handler)
        thread = ServerThread(server, f"WorkerMock(:{port})")
        thread.start()
        worker_threads.append(thread)
        logger.info(f"[INFO] Worker mock on port {port}")

    # Wait for all ports
    for port in [MOCK_K8S_PORT, MOCK_RENDER_PORT] + WORKER_PORTS:
        wait_for_port("127.0.0.1", port)

    logger.info("[INFO] All mock servers ready")

    # Write PID
    with open(args.pid_file, "w") as f:
        f.write(str(os.getpid()))

    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for publisher in worker_publishers.values():
            publisher.stop()
        k8s_server.shutdown()
        render_server.shutdown()
        for thread in worker_threads:
            thread.stop()


if __name__ == "__main__":
    main()
