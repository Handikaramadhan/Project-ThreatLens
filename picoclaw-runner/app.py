import os
import re
import secrets
import subprocess
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

PICOCLAW_BINARY = os.getenv("PICOCLAW_BINARY", "/usr/local/bin/picoclaw")
RUNNER_TOKEN = os.getenv("PICOCLAW_RUNNER_TOKEN", "")
RUN_TIMEOUT = int(os.getenv("PICOCLAW_RUN_TIMEOUT", "180"))
PICOCLAW_HOME = os.getenv("PICOCLAW_HOME", "/data")
PICOCLAW_CONFIG = os.getenv("PICOCLAW_CONFIG", str(Path(PICOCLAW_HOME) / "config.json"))
CONFIG_PATH = Path(PICOCLAW_CONFIG)
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,180}$")
ANSI_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

app = FastAPI(title="ThreatLens PicoClaw Runner", docs_url=None, redoc_url=None)


class AgentRequest(BaseModel):
    prompt: str = Field(min_length=2, max_length=12000)
    session_id: str = Field(min_length=1, max_length=180)
    model: str = Field(default="", max_length=160)


def _clean_output(value: str) -> str:
    lines = []
    for raw_line in ANSI_PATTERN.sub("", value).splitlines():
        line = raw_line.rstrip()
        if any(marker in line for marker in ("████", "██╔", "██║", "╚═╝")):
            continue
        if re.match(r"^\d{2}:\d{2}:\d{2}\s+(DBG|INF|WRN|ERR)\b", line):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


@app.get("/health")
def health() -> dict[str, object]:
    binary_ready = Path(PICOCLAW_BINARY).is_file()
    config_ready = CONFIG_PATH.is_file()
    ready = binary_ready and config_ready and bool(RUNNER_TOKEN)
    missing = []
    if not binary_ready:
        missing.append("binary")
    if not config_ready:
        missing.append("config")
    if not RUNNER_TOKEN:
        missing.append("runner token")
    return {
        "ready": ready,
        "service": "threatlens-picoclaw-runner",
        "message": "Ready" if ready else f"Missing: {', '.join(missing)}",
    }


@app.post("/v1/run")
def run_agent(
    payload: AgentRequest,
    x_runner_token: str | None = Header(default=None),
) -> dict[str, str]:
    if not RUNNER_TOKEN or not x_runner_token or not secrets.compare_digest(
        RUNNER_TOKEN,
        x_runner_token,
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid runner token")
    if not SESSION_PATTERN.fullmatch(payload.session_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid session id")
    if not CONFIG_PATH.is_file():
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="PicoClaw is not configured")

    command = [
        PICOCLAW_BINARY,
        "--no-color",
        "agent",
        "--message",
        payload.prompt,
        "--session",
        payload.session_id,
    ]
    if payload.model:
        command.extend(["--model", payload.model])
    environment = {
        "HOME": PICOCLAW_HOME,
        "PICOCLAW_HOME": PICOCLAW_HOME,
        "PICOCLAW_CONFIG": PICOCLAW_CONFIG,
        "NO_COLOR": "1",
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "LANG": "C.UTF-8",
    }
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env=environment,
            text=True,
            timeout=RUN_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="PicoClaw timed out",
        ) from exc
    if result.returncode != 0:
        detail = result.stderr.strip()[-1000:] or "PicoClaw failed"
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=detail)
    output = _clean_output(result.stdout)
    if not output:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="PicoClaw returned no output")
    return {"output": output}
