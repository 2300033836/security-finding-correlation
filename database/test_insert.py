import unittest

from database.db import (
    get_connection,
    insert_finding
)


class TestDatabaseInsert(unittest.TestCase):

    def test_insert_finding(self):

        finding = {
            "finding_id": "TEST_DB_001",
            "source_tool": "Nmap",
            "title": "Open SSH Port",
            "description": "SSH service is accessible on port 22",
            "severity": "medium",
            "host": "192.168.1.10",
            "port": 22
        }

        # Remove the test record if it already exists
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM findings
            WHERE finding_id = %s
            """,
            (finding["finding_id"],)
        )

        connection.commit()
        cursor.close()
        connection.close()

        # Insert the test finding
        insert_finding(finding)

        # Verify that the record exists
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT finding_id
            FROM findings
            WHERE finding_id = %s
            """,
            (finding["finding_id"],)
        )

        result = cursor.fetchone()

        cursor.close()
        connection.close()

        self.assertIsNotNone(result)

        # Clean up after the test
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM findings
            WHERE finding_id = %s
            """,
            (finding["finding_id"],)
        )

        connection.commit()
        cursor.close()
        connection.close()


if __name__ == "__main__":
    unittest.main()