"""
Charon HTTP API.

Accepts a file reference or URL, stores an investigation record, and runs
the agent loop (app/agent.py) on it in the background.
"""

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel

from app.agent import provider_api_key, provider_setting, refuse_openai_overrides, run_investigation
from app.db import get_connection

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # refuse to start without the provider key or with headers that could replace it, before touching the database
    provider_api_key()
    refuse_openai_overrides()
    # Background investigations die with the process, so any row still 'running' at startup is orphaned.
    # This assumes a single server process: with several workers, one worker's startup would mark the
    # others' in-flight investigations failed.
    with get_connection() as conn:
        orphaned = conn.execute(
            "UPDATE investigations SET status = 'failed', error = 'server restarted before completion'"
            " WHERE status = 'running'"
        ).rowcount
    logger.info("startup: marked %d orphaned 'running' investigation(s) failed", orphaned)
    yield


app = FastAPI(title="Charon", lifespan=lifespan)


class InvestigationCreate(BaseModel):
    submitted_input: str
    input_type: Literal["file", "url"]


class Investigation(BaseModel):
    id: int
    submitted_input: str
    input_type: str
    status: Literal["running", "complete", "incomplete", "failed"]
    report: Optional[str] = None
    error: Optional[str] = None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/investigations", response_model=Investigation)
def create_investigation(payload: InvestigationCreate, background_tasks: BackgroundTasks) -> Investigation:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO investigations (submitted_input, input_type, status, model)
                VALUES (%s, %s, 'running', %s)
                RETURNING id, submitted_input, input_type, status, report, error
                """,
                (payload.submitted_input, payload.input_type, provider_setting("MODEL")),
            )
            row = cur.fetchone()
        conn.commit()
    background_tasks.add_task(run_investigation, row[0])
    return Investigation(
        id=row[0], submitted_input=row[1], input_type=row[2], status=row[3], report=row[4], error=row[5]
    )


@app.get("/investigations/{investigation_id}", response_model=Investigation)
def get_investigation(investigation_id: int) -> Investigation:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, submitted_input, input_type, status, report, error
                FROM investigations WHERE id = %s
                """,
                (investigation_id,),
            )
            row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="investigation not found")
    return Investigation(
        id=row[0], submitted_input=row[1], input_type=row[2], status=row[3], report=row[4], error=row[5]
    )
