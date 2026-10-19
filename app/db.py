import os

import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]


def get_connection() -> psycopg.Connection:
    """Open a new connection. There is no connection pool and no connect timeout."""
    return psycopg.connect(DATABASE_URL)
