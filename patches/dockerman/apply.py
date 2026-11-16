#!/usr/bin/env python3
"""Apply the narrowly scoped 25.12 Dockerman RPC hotfix to an exact source."""

import argparse
import hashlib
from pathlib import Path

SOURCE_COMMIT = "1c75ea46c68ebc386fef9922089260de16f30417"
SOURCE_SHA256 = "f9c8482fb58d6d56d9b749f9206513b24c169fd8cb59e0619a29b7f2a2b55381"
POLL_REFERENCE = "3abb5aa82c4baaec3a9f80dcfecf210ea101df6f"
PATCH_VERSION = "25.12-rpc-hang-v1"


def patch_source(source):
    digest = hashlib.sha256(source).hexdigest()
    if digest != SOURCE_SHA256:
        raise ValueError(f"Unsupported docker_rpc.uc SHA-256: {digest}")
    text = source.decode("utf-8")

    def replace(old, new):
        nonlocal text
        count = text.count(old)
        if count != 1:
            raise ValueError(f"Expected exactly one source anchor, found {count}: {old!r}")
        text = text.replace(old, new, 1)

    replace(
        "const POLL_TIMEOUT = 8000; // default; can be overridden per request",
        "const POLL_TIMEOUT = 8000; // default; can be overridden per request\n"
        "const MAX_CHANGES_BYTES = 512 * 1024; // Bound Changes before JSON/ubus",
    )
    replace(
        "function chunked_body_reader(sock, initial_buffer) {\n"
        "\tlet state = 0, chunklen = 0, buffer = initial_buffer || '';",
        """// A timeout can return [[sock, 0]]; only POLLIN permits a blocking recv().
function wait_readable(sock) {
	const ready = socket.poll(POLL_TIMEOUT, [sock, socket.POLLIN]);
	return !!(ready && length(ready) && (ready[0][1] & socket.POLLIN));
};

function chunked_body_reader(sock, initial_buffer, limit) {
	let state = 0, chunklen = 0, buffer = initial_buffer || '';
	let body_bytes = 0;""",
    )
    replace(
        """		let ready = socket.poll(POLL_TIMEOUT, [sock, socket.POLLIN]);
		if (!ready || !length(ready)) return null;
		let data = sock.recv(BLOCKSIZE);
		if (!data) return null;
		buffer += data;""",
        """		if (!wait_readable(sock)) return null;
		let data = sock.recv(BLOCKSIZE);
		if (!data) return null;
		// Also bound malformed chunk headers; never buffer an unbounded chunk.
		if (limit && length(buffer) + length(data) > MAX_CHANGES_BYTES + BLOCKSIZE) {
			limit.exceeded = true;
			return null;
		}
		buffer += data;""",
    )
    replace(
        "\t\t\t\tchunklen = int(m[1], 16);\n\t\t\t\tbuffer = substr(buffer, length(m[0]));",
        """				chunklen = int(m[1], 16);
				// Check BEFORE the original reader collects the complete chunk.
				if (limit && chunklen > MAX_CHANGES_BYTES - body_bytes) {
					limit.exceeded = true;
					return null;
				}
				body_bytes += chunklen;
				buffer = substr(buffer, length(m[0]));""",
    )
    replace(
        "\tconst response_buff = sock.recv(BLOCKSIZE);",
        """	if (!wait_readable(sock)) {
		sock.close();
		return {
			code: 504,
			headers: {},
			body: { message: 'Timeout waiting for response from Docker socket' }
		};
	}

	const response_buff = sock.recv(BLOCKSIZE);""",
    )
    replace(
        "\tlet reader;\n\tif (is_chunked) {\n\t\treader = chunked_body_reader(sock, response_parts[1]);",
        """	const is_changes = method == 'GET' && match(path, /^\\/containers\\/[^/]+\\/changes$/);
	const changes_limit = is_changes ? { exceeded: false } : null;

	function too_large_response() {
		sock.close();
		return {
			code: 413,
			headers: {},
			body: { message: 'Changes response exceeds 512 KiB; use docker diff via SSH' }
		};
	}

	if (is_changes && int(response_headers['content-length']) > MAX_CHANGES_BYTES)
		return too_large_response();

	let reader;
	if (is_chunked) {
		reader = chunked_body_reader(sock, response_parts[1], changes_limit);""",
    )
    replace(
        "\t\t\tlet data = sock.recv(min(BLOCKSIZE, content_length));",
        "\t\t\tif (!wait_readable(sock)) return null; // Timeout or error\n\n"
        "\t\t\tlet data = sock.recv(min(BLOCKSIZE, content_length));",
    )
    replace(
        """		// Fallback for HTTP/1.0 or no content-length: read until close or timeout
		reader = () => {
			// Poll with 2 second timeout
			let ready = socket.poll(POLL_TIMEOUT, [sock, socket.POLLIN]);
			if (!ready || !length(ready)) return null; // Timeout or error
""",
        """		// Fallback for HTTP/1.0 or no content-length: read until close or timeout
		let buf = response_parts[1];
		reader = () => {
			// Include the body bytes already received with the headers.
			if (buf && length(buf)) {
				let data = buf;
				buf = null;
				return data;
			}
			if (!wait_readable(sock)) return null; // Timeout or error
""",
    )
    replace(
        """	let chunks = [], chunk;
	while ((chunk = reader())) {
		push(chunks, chunk);
	}

	sock.close();""",
        """	let chunks = [], chunk;
	let response_bytes = 0;
	while ((chunk = reader())) {
		response_bytes += length(chunk);
		if (is_changes && response_bytes > MAX_CHANGES_BYTES)
			return too_large_response();
		push(chunks, chunk);
	}

	if (changes_limit && changes_limit.exceeded)
		return too_large_response();

	sock.close();""",
    )
    # Fail closed if the pinned source or patch ever changes these assumptions.
    expected_counts = {
        "socket.poll(": 1,
        "sock.recv(": 4,
        "if (!wait_readable(sock))": 4,
        "code: 504,": 1,
        "code: 413,": 1,
        "const MAX_CHANGES_BYTES = 512 * 1024;": 1,
        "return too_large_response();": 3,
    }
    for marker, count in expected_counts.items():
        if text.count(marker) != count:
            raise ValueError(f"Hotfix invariant failed: {marker!r}")
    return text.encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="unmodified, pinned docker_rpc.uc")
    parser.add_argument("output", type=Path, help="ImageBuilder FILES overlay path")
    args = parser.parse_args()
    try:
        patched = patch_source(args.source.read_bytes())
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(1, f"Dockerman hotfix refused: {exc}\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    args.output.chmod(0o755)
    print(f"Dockerman hotfix: {PATCH_VERSION}")
    print(f"Source commit: {SOURCE_COMMIT}")
    print(f"Source SHA-256: {SOURCE_SHA256}")
    print(f"Poll fix reference: {POLL_REFERENCE}")
    print(f"Output SHA-256: {hashlib.sha256(patched).hexdigest()}")


if __name__ == "__main__":
    main()
