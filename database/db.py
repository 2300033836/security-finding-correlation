
import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv()


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    connection = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME", "security_findings")
    )
    return connection


# ============================================================
# INSERT ONE FINDING
# ============================================================

def insert_finding(finding):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        INSERT INTO findings (
            finding_id,
            source_tool,
            title,
            description,
            severity,
            host,
            port
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """

    if "source_tools" in finding:
        source_tool = ", ".join(finding["source_tools"])
    else:
        source_tool = finding["source_tool"]

    values = (
        finding["finding_id"],
        source_tool,
        finding["title"],
        finding["description"],
        finding["severity"],
        finding["host"],
        finding["port"]
    )

    cursor.execute(query, values)

    connection.commit()

    cursor.close()
    connection.close()


# ============================================================
# INSERT MULTIPLE FINDINGS
# ============================================================

def insert_findings(findings):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        INSERT IGNORE INTO findings (
            finding_id,
            source_tool,
            title,
            description,
            severity,
            host,
            port
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """

    for finding in findings:

        if "source_tools" in finding:
            source_tool = ", ".join(finding["source_tools"])
        else:
            source_tool = finding["source_tool"]

        values = (
            finding["finding_id"],
            source_tool,
            finding["title"],
            finding["description"],
            finding["severity"],
            finding["host"],
            finding["port"]
        )

        cursor.execute(query, values)

    connection.commit()

    cursor.close()
    connection.close()


# ============================================================
# INSERT DUPLICATE MATCHES
# ============================================================

def insert_duplicate_matches(duplicate_pairs):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        INSERT IGNORE INTO duplicate_matches (
            finding1_id,
            finding2_id,
            similarity
        )
        VALUES (%s, %s, %s)
    """

    for pair in duplicate_pairs:

        values = (
            pair["finding1"],
            pair["finding2"],
            pair["similarity"]
        )

        cursor.execute(query, values)

    connection.commit()

    cursor.close()
    connection.close()


# ============================================================
# INSERT CORRELATIONS
# ============================================================

def insert_correlations(correlations):

    connection = get_connection()
    cursor = connection.cursor()

    query = """
        INSERT IGNORE INTO correlations (
            finding1_id,
            finding2_id,
            reason
        )
        VALUES (%s, %s, %s)
    """

    for correlation in correlations:

        values = (
            correlation["finding1"],
            correlation["finding2"],
            correlation["reason"]
        )

        cursor.execute(query, values)

    connection.commit()

    cursor.close()
    connection.close()


# ============================================================
# GET ALL FINDINGS
# ============================================================

def get_all_findings():

    connection = get_connection()

    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT
            finding_id,
            source_tool,
            title,
            description,
            severity,
            host,
            port,
            created_at
        FROM findings
        ORDER BY id
    """

    cursor.execute(query)

    findings = cursor.fetchall()

    cursor.close()
    connection.close()

    return findings


# ============================================================
# GET DUPLICATE MATCHES
# ============================================================

def get_duplicate_matches():

    connection = get_connection()

    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT
            dm.finding1_id,
            dm.finding2_id,
            dm.similarity,

            f1.host AS host1,
            f2.host AS host2,

            f1.port AS port1,
            f2.port AS port2,

            f1.source_tool AS source_tool1,
            f2.source_tool AS source_tool2

        FROM duplicate_matches dm

        LEFT JOIN findings f1
            ON dm.finding1_id = f1.finding_id

        LEFT JOIN findings f2
            ON dm.finding2_id = f2.finding_id

        ORDER BY dm.id
    """

    cursor.execute(query)

    duplicates = cursor.fetchall()

    cursor.close()
    connection.close()

    return duplicates


# ============================================================
# GET CORRELATIONS
# ============================================================

def get_correlations():

    connection = get_connection()

    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT
            finding1_id,
            finding2_id,
            reason
        FROM correlations
        ORDER BY id
    """

    cursor.execute(query)

    correlations = cursor.fetchall()

    cursor.close()
    connection.close()

    return correlations


# ============================================================
# CLEAR PREVIOUS PIPELINE RESULTS
# ============================================================

def clear_pipeline_results():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM correlations")
    cursor.execute("DELETE FROM duplicate_matches")
    cursor.execute("DELETE FROM findings")

    connection.commit()

    cursor.close()
    connection.close()
