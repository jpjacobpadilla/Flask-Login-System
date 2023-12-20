import sqlite3
import contextlib
from pathlib import Path


def create_connection(db_file: str) -> None:
    """ Create a database connection to a SQLite database """
    try:
        conn = sqlite3.connect(db_file)
    finally:
        conn.close()


def create_table(db_file: str) -> None:
    """ Create a table for users """
    query = '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT
        );
    ''' 

    with contextlib.closing(sqlite3.connect(db_file)) as conn:
        with conn:
            conn.execute(query)


def setup_database(name: str) -> None:
    if Path(name).exists():
        return

    create_connection(name)
    create_table(name)
    print('Created new example database.')
    
