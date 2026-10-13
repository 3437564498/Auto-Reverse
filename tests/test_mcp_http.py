import asyncio
import socket
import subprocess
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from auto_reverse.service import RecoveryService


def test_real_streamable_http_handshake_submit_and_reconnect(tmp_path):
    state = tmp_path / "state"
    service = RecoveryService(state)
    source = tmp_path / "staged.so"
    source.write_bytes(b"opaque staged input; intake occurs in the worker")
    registered = service.register_input(source)
    policy = service.register_policy()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    process = subprocess.Popen([
        sys.executable, "-m", "auto_reverse.cli", "--state-dir", str(state),
        "mcp", "--transport", "streamable-http", "--port", str(port),
    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    async def exercise():
        url = f"http://127.0.0.1:{port}/mcp"
        for _ in range(100):
            if process.poll() is not None:
                raise AssertionError(process.stderr.read().decode())
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                break
            except OSError:
                await asyncio.sleep(0.05)
        else:
            raise AssertionError("MCP server did not become ready")
        arguments = {"input_ref": registered["input_ref"], "policy_ref": policy["policy_ref"],
                     "idempotency_key": "http-reconnect"}
        async with streamable_http_client(url) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.list_tools()
                assert service.domain.list_jobs()["items"] == []
                result = await session.call_tool("submit_job", arguments)
                assert not result.isError
                job_id = result.structuredContent["job_id"]
        async with streamable_http_client(url) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("submit_job", arguments)
                assert result.structuredContent["job_id"] == job_id
                view = await session.call_tool("get_job", {"job_id": job_id})
                assert view.structuredContent["execution_state"] == "QUEUED"

    try:
        asyncio.run(exercise())
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        process.stderr.close()
