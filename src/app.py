from pathlib import Path

from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file
)
from werkzeug.utils import secure_filename

from database.db import (
    get_all_findings,
    get_duplicate_matches,
    get_correlations
)

from src.pipeline import run_pipeline


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_DIR = BASE_DIR / "input"
REPORTS_DIR = BASE_DIR / "reports"

INPUT_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates")
)


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({
        "message": "Security Finding Correlation API",
        "status": "running"
    })


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    return render_template(
        "dashboard.html"
    )


# ============================================================
# GET FINDINGS
# ============================================================

@app.route("/findings")
def findings():

    return jsonify(
        get_all_findings()
    )


# ============================================================
# GET DUPLICATES
# ============================================================

@app.route("/duplicates")
def duplicates():

    return jsonify(
        get_duplicate_matches()
    )


# ============================================================
# GET CORRELATIONS
# ============================================================

@app.route("/correlations")
def correlations():

    return jsonify(
        get_correlations()
    )


# ============================================================
# UPLOAD SECURITY FINDING FILES
# ============================================================

@app.route(
    "/upload-files",
    methods=["POST"]
)
def upload_files():

    try:

        uploaded_files = {
            "nmap": request.files.get("nmap_file"),
            "nuclei": request.files.get("nuclei_file"),
            "semgrep": request.files.get("semgrep_file")
        }

        uploaded_count = 0

        for tool_name, uploaded_file in uploaded_files.items():

            if uploaded_file is None:
                continue

            if uploaded_file.filename == "":
                continue

            original_name = secure_filename(
                uploaded_file.filename
            )

            file_extension = Path(
                original_name
            ).suffix.lower()

            # ------------------------------------------------
            # Allowed file formats
            # ------------------------------------------------

            if tool_name == "nmap":

                allowed_extensions = [
                    ".json",
                    ".xml"
                ]

            else:

                allowed_extensions = [
                    ".json"
                ]

            if file_extension not in allowed_extensions:

                return jsonify({

                    "status": "error",

                    "message":
                        f"{tool_name} file must be one of: "
                        + ", ".join(
                            allowed_extensions
                        )

                }), 400

            # ------------------------------------------------
            # Destination file
            # ------------------------------------------------

            if tool_name == "nmap":

                if file_extension == ".xml":

                    destination = (
                        INPUT_DIR
                        / "nmap_results.xml"
                    )

                    # Remove old JSON Nmap file
                    old_json_file = (
                        INPUT_DIR
                        / "nmap_results.json"
                    )

                    if old_json_file.exists():
                        old_json_file.unlink()

                else:

                    destination = (
                        INPUT_DIR
                        / "nmap_results.json"
                    )

                    # Remove old XML Nmap file
                    old_xml_file = (
                        INPUT_DIR
                        / "nmap_results.xml"
                    )

                    if old_xml_file.exists():
                        old_xml_file.unlink()

            elif tool_name == "nuclei":

                destination = (
                    INPUT_DIR
                    / "nuclei_results.json"
                )

            else:

                destination = (
                    INPUT_DIR
                    / "semgrep_results.json"
                )

            uploaded_file.save(
                destination
            )

            uploaded_count += 1

        if uploaded_count == 0:

            return jsonify({

                "status": "error",

                "message":
                    "No files were uploaded"

            }), 400

        return jsonify({

            "status": "success",

            "message":
                f"{uploaded_count} file(s) uploaded successfully",

            "uploaded_count":
                uploaded_count

        })

    except Exception as error:

        return jsonify({

            "status": "error",

            "message":
                str(error)

        }), 500


# ============================================================
# RUN PIPELINE
# ============================================================

@app.route("/run-pipeline")
def run_pipeline_api():

    try:

        # ------------------------------------------------
        # Find the currently uploaded Nmap file
        # ------------------------------------------------

        nmap_xml_file = (
            INPUT_DIR
            / "nmap_results.xml"
        )

        nmap_json_file = (
            INPUT_DIR
            / "nmap_results.json"
        )

        if nmap_xml_file.exists():

            nmap_file = nmap_xml_file

        elif nmap_json_file.exists():

            nmap_file = nmap_json_file

        else:

            nmap_file = None

        # ------------------------------------------------
        # Other tool files
        # ------------------------------------------------

        nuclei_file = (
            INPUT_DIR
            / "nuclei_results.json"
        )

        semgrep_file = (
            INPUT_DIR
            / "semgrep_results.json"
        )

        missing_files = []

        if nmap_file is None:

            missing_files.append(
                "Nmap XML/JSON"
            )

        if not nuclei_file.exists():

            missing_files.append(
                "Nuclei JSON"
            )

        if not semgrep_file.exists():

            missing_files.append(
                "Semgrep JSON"
            )

        if missing_files:

            return jsonify({

                "status": "error",

                "message":
                    "Missing input file(s): "
                    + ", ".join(
                        missing_files
                    )

            }), 400

        # ------------------------------------------------
        # Run complete pipeline
        # ------------------------------------------------

        result = run_pipeline(

            (
                str(nmap_file),
                str(nuclei_file),
                str(semgrep_file)
            ),

            "multi"
        )

        return jsonify({

            "status": "success",

            "message":
                "Multi-tool pipeline executed successfully",

            "original_count":
                result["original_count"],

            "duplicate_count":
                len(
                    result["duplicate_pairs"]
                ),

            "merged_count":
                len(
                    result["merged_findings"]
                ),

            "correlation_count":
                len(
                    result["correlations"]
                )

        })

    except Exception as error:

        return jsonify({

            "status": "error",

            "message":
                str(error)

        }), 500


# ============================================================
# DOWNLOAD SECURITY REPORT
# ============================================================

@app.route("/download-report")
def download_report():

    report_file = (
        REPORTS_DIR
        / "security_report.json"
    )

    if not report_file.exists():

        return jsonify({

            "status": "error",

            "message":
                "Security report not found"

        }), 404

    return send_file(

        report_file,

        as_attachment=True,

        download_name=
            "security_report.json",

        mimetype=
            "application/json"
    )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )