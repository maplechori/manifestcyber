"""PostgreSQL persistence implemented using SQLAlchemy Core."""

from abc import ABC, abstractmethod
from contextlib import contextmanager

from sqlalchemy import (
    Column,
    ForeignKey,
    Integer,
    MetaData,
    Table,
    Text,
    create_engine,
    delete,
    func,
    insert,
    select,
)
from sqlalchemy.dialects.postgresql import aggregate_order_by
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError


class DatabaseError(Exception):
    pass


metadata = MetaData()
documents = Table(
    "documents",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("source", Text, nullable=False, unique=True),
    Column("name", Text, nullable=False),
)
components_table = Table(
    "components",
    metadata,
    Column("id", Integer, primary_key=True),
    Column(
        "document_id",
        Integer,
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("name", Text, nullable=False),
    Column("version", Text),
)
licenses_table = Table(
    "licenses",
    metadata,
    Column(
        "component_id",
        Integer,
        ForeignKey("components.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("value", Text, primary_key=True),
)


class Database(ABC):
    @abstractmethod
    def initialize(self):
        """Explicitly create the schema, preserving existing data."""

    @abstractmethod
    def replace_document(self, source, name, components):
        """Consume a component iterable atomically; return the inserted count."""

    @abstractmethod
    def query(self, component=None, version=None, license_value=None):
        """Find documents by component or components by license."""

    @abstractmethod
    def list_components(self):
        """List distinct components with versions and owning documents."""

    @abstractmethod
    def list_licenses(self):
        """List distinct stored license values."""

    @abstractmethod
    def close(self):
        pass


class SQLAlchemyDatabase(Database):
    def __init__(self, url):
        try:
            self.engine = create_engine(url)
        except ImportError as exc:
            raise DatabaseError("PostgreSQL driver missing; run uv sync") from exc
        except SQLAlchemyError as exc:
            raise DatabaseError(str(exc)) from exc

    @contextmanager
    def transaction(self):
        try:
            with self.engine.begin() as connection:
                yield connection
        except SQLAlchemyError as exc:
            raise DatabaseError(str(exc)) from exc

    def initialize(self):
        with self.transaction() as connection:
            metadata.create_all(connection)

    def replace_document(self, source, name, components):
        with self.transaction() as connection:
            connection.execute(delete(documents).where(documents.c.source == source))
            document_id = connection.execute(
                insert(documents).values(source=source, name=name)
            ).inserted_primary_key[0]
            count = 0
            for component_name, version, licenses in components:
                count += 1
                component_id = connection.execute(
                    insert(components_table).values(
                        document_id=document_id, name=component_name, version=version
                    )
                ).inserted_primary_key[0]
                if licenses:
                    connection.execute(
                        insert(licenses_table),
                        [
                            {"component_id": component_id, "value": value}
                            for value in licenses
                        ],
                    )

        return count

    def query(self, component=None, version=None, license_value=None):
        d, c, license_columns = documents.c, components_table.c, licenses_table.c
        owner = documents.join(components_table)
        if component is not None:
            statement = (
                select(
                    c.name.label("component"),
                    c.version,
                    d.name.label("document"),
                    d.source,
                )
                .select_from(owner)
                .where(c.name.icontains(component, autoescape=True))
            )
            if version is not None:
                statement = statement.where(c.version == version)
            statement = statement.distinct().order_by(
                d.name, d.source, c.name, c.version
            )
        else:
            statement = (
                select(
                    c.name.label("component"),
                    c.version,
                    license_columns.value.label("license"),
                    d.name.label("document"),
                    d.source,
                )
                .select_from(owner.join(licenses_table))
                .where(license_columns.value == license_value)
                .distinct()
                .order_by(d.name, d.source, c.name, c.version)
            )
        with self.transaction() as connection:
            return [dict(row) for row in connection.execute(statement).mappings()]

    def list_components(self):
        d, c, licenses = documents.c, components_table.c, licenses_table.c
        statement = (
            select(
                c.name.label("component"),
                c.version,
                d.name.label("document"),
                d.source,
                func.array_agg(
                    aggregate_order_by(licenses.value.distinct(), licenses.value)
                )
                .filter(licenses.value.is_not(None))
                .label("licenses"),
            )
            .select_from(documents.join(components_table).outerjoin(licenses_table))
            .group_by(c.name, c.version, d.name, d.source)
            .order_by(c.name, c.version, d.name, d.source)
        )
        with self.transaction() as connection:
            return [
                {**row, "licenses": row["licenses"] or []}
                for row in connection.execute(statement).mappings()
            ]

    def list_licenses(self):
        statement = (
            select(licenses_table.c.value).distinct().order_by(licenses_table.c.value)
        )
        with self.transaction() as connection:
            return list(connection.execute(statement).scalars())

    def close(self):
        self.engine.dispose()


def open_database(target):
    if not target.startswith(("postgresql://", "postgres://", "postgresql+psycopg://")):
        raise ValueError("SBOM_DATABASE must be a PostgreSQL URL")
    if target.startswith("postgres://"):
        target = "postgresql://" + target[len("postgres://") :]
    return SQLAlchemyDatabase(make_url(target).set(drivername="postgresql+psycopg"))
