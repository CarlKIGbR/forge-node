"""Datenbankzugang des Hubs (psycopg 3, Rolle forge_nodehub). Verbindung je Operation aus einem kleinen Pool; Passwort nur aus Datei."""
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row


def read_password(path: Path | None) -> str | None:
    if path is None:
        return None
    return Path(path).read_text().rstrip("\r\n")


class Db:
    def __init__(self, dsn: str, password_file: Path | None = None, max_size: int = 8):
        from psycopg_pool import ConnectionPool

        kwargs = {"row_factory": dict_row}
        pw = read_password(password_file)
        if pw:
            kwargs["password"] = pw
        self.pool = ConnectionPool(dsn, kwargs=kwargs, min_size=1, max_size=max_size, open=True, timeout=15)

    @contextmanager
    def tx(self):
        """Eine Transaktion; Commit bei normalem Ende, Rollback bei Ausnahme."""
        with self.pool.connection() as conn:
            with conn.transaction():
                yield conn

    def close(self):
        self.pool.close()


class DirectDb:
    """Ohne Pool (Tests, Migration): jede tx() oeffnet eine eigene Verbindung."""

    def __init__(self, dsn: str, password: str | None = None, role: str | None = None):
        self.dsn, self.password, self.role = dsn, password, role

    def connect(self):
        kw = {"row_factory": dict_row, "autocommit": False}
        if self.password:
            kw["password"] = self.password
        conn = psycopg.connect(self.dsn, **kw)
        if self.role:
            conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(self.role)))
            conn.commit()
        return conn

    @contextmanager
    def tx(self):
        conn = self.connect()
        try:
            with conn.transaction():
                yield conn
        finally:
            conn.close()

    def close(self):
        pass
