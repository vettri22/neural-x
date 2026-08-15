"""
Lightweight additive auto-migration.

This project uses Flask-Migrate/Alembic for formal migrations, but no
migrations directory ships in this snapshot. To avoid destroying existing
data while still delivering the v4 schema additions out of the box, this
helper inspects the live database and ADDS any missing nullable columns
declared on the SQLAlchemy models. It never drops or alters existing
columns and never touches existing rows (new columns come back as NULL for
old rows, which every v4 code path already treats as "not yet analyzed").

For a permanent, reviewable migration, generate a real Alembic revision:
    flask db migrate -m "v4 risk fusion columns"
    flask db upgrade
This helper is a safety net for deployments that skip that step.
"""

import logging
from sqlalchemy import inspect, text

logger = logging.getLogger(__name__)

# SQLite/Postgres-compatible column type strings for ALTER TABLE.
_SQL_TYPE = {
    'Float': 'FLOAT',
    'Text': 'TEXT',
    'String': 'VARCHAR(255)',
}


def ensure_new_columns(db, model, column_specs):
    """
    column_specs: list of (column_name, sql_type_key) tuples, e.g.
        [('visual_risk', 'Float'), ('risk_level', 'String')]
    """
    try:
        inspector = inspect(db.engine)
        table_name = model.__tablename__
        if table_name not in inspector.get_table_names():
            return  # fresh DB — db.create_all() already created it with all columns

        existing = {c['name'] for c in inspector.get_columns(table_name)}
        missing = [(name, kind) for name, kind in column_specs if name not in existing]
        if not missing:
            return

        with db.engine.begin() as conn:
            for name, kind in missing:
                sql_type = _SQL_TYPE.get(kind, 'TEXT')
                try:
                    conn.execute(text(
                        f'ALTER TABLE {table_name} ADD COLUMN {name} {sql_type}'
                    ))
                    logger.info(f'Auto-migration: added column {table_name}.{name} ({sql_type})')
                except Exception as e:
                    logger.warning(f'Auto-migration: could not add {table_name}.{name}: {e}')
    except Exception as e:
        logger.warning(f'Auto-migration inspection failed: {e}')
