import unittest
from unittest import mock

import pytest

from kinto.core.permission import PermissionBase
from kinto.core.permission import memory as memory_backend
from kinto.core.permission import postgresql as postgresql_backend
from kinto.core.permission.testing import PermissionTest
from kinto.core.testing import skip_if_no_postgresql
from kinto.core.utils import sqlalchemy


class PermissionBaseTest(unittest.TestCase):
    def setUp(self):
        self.permission = PermissionBase()

    def test_mandatory_overrides(self):
        calls = [
            (self.permission.initialize_schema,),
            (self.permission.flush,),
            (self.permission.add_user_principal, "", ""),
            (self.permission.remove_user_principal, "", ""),
            (self.permission.remove_principal, ""),
            (self.permission.get_user_principals, ""),
            (self.permission.add_principal_to_ace, "", "", ""),
            (self.permission.remove_principal_from_ace, "", "", ""),
            (self.permission.get_object_permission_principals, "", ""),
            (self.permission.get_objects_permissions, ""),
            (self.permission.replace_object_permissions, "", {}),
            (self.permission.delete_object_permissions, ""),
            (self.permission.get_accessible_objects, [], ""),
            (self.permission.get_authorized_principals, []),
        ]
        for callable_, *args in calls:
            self.assertRaises(NotImplementedError, callable_, *args)


class MemoryPermissionTest(PermissionTest, unittest.TestCase):
    backend = memory_backend

    def test_backend_error_is_raised_anywhere(self):
        pass

    def test_ping_returns_false_if_unavailable(self):
        pass

    def test_ping_logs_error_if_unavailable(self):
        pass


@pytest.mark.xdist_group("postgres")
@skip_if_no_postgresql
class PostgreSQLPermissionTest(PermissionTest, unittest.TestCase):
    backend = postgresql_backend
    settings = {
        "permission_backend": "kinto.core.permission.postgresql",
        "permission_pool_size": 10,
        "permission_url": "postgresql://postgres:postgres@localhost:5432/testdb",
    }

    def setUp(self):
        super().setUp()
        self.client_error_patcher = [
            mock.patch.object(
                self.permission.client,
                "session_factory",
                side_effect=sqlalchemy.exc.SQLAlchemyError,  # type: ignore[possibly-missing-attribute]
            )
        ]

    def _explain_accessible_objects(self, *args, **kwargs):
        """Run get_accessible_objects() and return the plan of its SQL query."""
        captured = []

        def capture(conn, cursor, statement, parameters, context, executemany):
            if "access_control_entries" in statement:
                captured.append((statement, parameters))

        sqlalchemy.event.listen(sqlalchemy.engine.Engine, "before_cursor_execute", capture)
        try:
            self.permission.get_accessible_objects(*args, **kwargs)
        finally:
            sqlalchemy.event.remove(sqlalchemy.engine.Engine, "before_cursor_execute", capture)

        statement, parameters = captured[-1]
        with self.permission.client.connect(readonly=True) as session:
            conn = session.connection()
            # Tiny test tables make a sequential scan cheapest; we only check
            # that the partial index is usable by the generated SQL.
            conn.exec_driver_sql("SET LOCAL enable_seqscan = off")
            rows = conn.exec_driver_sql("EXPLAIN " + statement, parameters).fetchall()
        return "\n".join(r[0] for r in rows)

    def _add_history_heavy_aces(self):
        query = """
        INSERT INTO access_control_entries (object_id, permission, principal)
        SELECT '/buckets/b' || (i % 20) || '/history/h' || i, 'read', 'admins'
          FROM generate_series(1, 3000) i
        UNION ALL
        SELECT '/buckets/b' || i, 'write', 'admins'
          FROM generate_series(1, 20) i;
        ANALYZE access_control_entries;
        """
        with self.permission.client.connect(force_commit=True) as conn:
            conn.execute(sqlalchemy.text(query))

    def test_accessible_objects_ignoring_history_uses_partial_index(self):
        self._add_history_heavy_aces()
        plan = self._explain_accessible_objects(
            ["admins"],
            [("/buckets/*", "read"), ("/buckets/*", "write")],
            with_children=False,
            ignore_history=True,
        )
        self.assertIn("idx_ace_principal_nohistory", plan)

    def test_unbound_accessible_objects_ignoring_history_uses_partial_index(self):
        self._add_history_heavy_aces()
        plan = self._explain_accessible_objects(["admins"], ignore_history=True)
        self.assertIn("idx_ace_principal_nohistory", plan)
