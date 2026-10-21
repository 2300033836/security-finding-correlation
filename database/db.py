import mysql.connector


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="sushma",
        database="security_findings"
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


    # Normal finding uses source_tool.
    # Merged finding uses source_tools.

    if "source_tools" in finding:

        source_tool = ", ".join(
            finding["source_tools"]
        )

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


    cursor.execute(
        query,
        values
    )


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

        # ------------------------------------------
        # Handle merged findings
        # ------------------------------------------

        if "source_tools" in finding:

            source_tool = ", ".join(
                finding["source_tools"]
            )


        # ------------------------------------------
        # Handle normal findings
        # ------------------------------------------

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


        cursor.execute(
            query,
            values
        )


    connection.commit()


    cursor.close()
    connection.close()


# ============================================================
# INSERT DUPLICATE MATCHES
# ============================================================

def insert_duplicate_matches(
    duplicate_pairs
):

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


        cursor.execute(
            query,
            values
        )


    connection.commit()


    cursor.close()
    connection.close()


# ============================================================
# INSERT CORRELATIONS
# ============================================================

def insert_correlations(
    correlations
):

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


        cursor.execute(
            query,
            values
        )


    connection.commit()


    cursor.close()
    connection.close()


# ============================================================
# GET ALL FINDINGS
# ============================================================

def get_all_findings():

    connection = get_connection()

    cursor = connection.cursor(
        dictionary=True
    )


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


    cursor.execute(
        query
    )


    findings = cursor.fetchall()


    cursor.close()
    connection.close()


    return findings


# ============================================================
# GET DUPLICATE MATCHES
# ============================================================

def get_duplicate_matches():

    connection = get_connection()

    cursor = connection.cursor(
        dictionary=True
    )


    query = """
        SELECT
            finding1_id,
            finding2_id,
            similarity
        FROM duplicate_matches
        ORDER BY id
    """


    cursor.execute(
        query
    )


    duplicates = cursor.fetchall()


    cursor.close()
    connection.close()


    return duplicates


# ============================================================
# GET CORRELATIONS
# ============================================================

def get_correlations():

    connection = get_connection()

    cursor = connection.cursor(
        dictionary=True
    )


    query = """
        SELECT
            finding1_id,
            finding2_id,
            reason
        FROM correlations
        ORDER BY id
    """


    cursor.execute(
        query
    )


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

    cursor.execute(
        "DELETE FROM correlations"
    )

    cursor.execute(
        "DELETE FROM duplicate_matches"
    )

    cursor.execute(
        "DELETE FROM findings"
    )

    connection.commit()

    cursor.close()
    connection.close()