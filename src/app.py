
from pathlib import Path
import json

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
    get_correlations,
    clear_pipeline_results
)

from src.pipeline import run_pipeline


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_DIR = BASE_DIR / "input"
REPORTS_DIR = BASE_DIR / "reports"

INPUT_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

REPORT_FILE = REPORTS_DIR / "security_report.json"

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates")
)

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


# ============================================================
# HOME AND DASHBOARD
# ============================================================

@app.route("/")
def home():
    return jsonify({
        "message": "Security Finding Correlation API",
        "status": "running"
    })


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ============================================================
# DASHBOARD DATA
# ============================================================

@app.route("/findings")
def findings():
    return jsonify(get_all_findings())


@app.route("/duplicates")
def duplicates():
    return jsonify(get_duplicate_matches())


@app.route("/correlations")
def correlations():
    return jsonify(get_correlations())


@app.route("/pipeline-summary")
def pipeline_summary():

    if not REPORT_FILE.exists():
        return jsonify({
            "status": "no_report",
            "summary": {
                "original_findings": 0,
                "duplicate_matches": 0,
                "consolidated_findings": 0,
                "correlations": 0
            }
        })

    try:
        with open(REPORT_FILE, "r", encoding="utf-8") as file:
            report = json.load(file)

        return jsonify({
            "status": "success",
            "metadata": report.get("metadata", {}),
            "summary": report.get("summary", {})
        })

    except (json.JSONDecodeError, OSError) as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500


# ============================================================
# CLEAR ALL PREVIOUS RESULTS AND INPUT FILES
# ============================================================

@app.route("/clear-results", methods=["POST"])
def clear_results():

    try:
        # 1. Clear previous database results
        clear_pipeline_results()

        # 2. Delete uploaded Nmap, Nuclei and Semgrep files
        input_files = [
            "nmap_results.json",
            "nmap_results.xml",
            "nuclei_results.json",
            "nuclei_results.jsonl",
            "semgrep_results.json"
        ]

        for filename in input_files:
            file_path = INPUT_DIR / filename

            if file_path.exists():
                file_path.unlink()

        # 3. Remove previous JSON report
        if REPORT_FILE.exists():
            REPORT_FILE.unlink()

        return jsonify({
            "status": "success",
            "message": "All previous results and uploaded input files cleared successfully."
        })

    except Exception as error:
        app.logger.exception("Failed to clear results")

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500


# ============================================================
# UPLOAD SECURITY REPORTS
# ============================================================

@app.route("/upload-files", methods=["POST"])
def upload_files():

    try:
        uploaded_files = {
            "nmap": request.files.get("nmap_file"),
            "nuclei": request.files.get("nuclei_file"),
            "semgrep": request.files.get("semgrep_file")
        }

        allowed_formats = {
            "nmap": [".json", ".xml"],
            "nuclei": [".json", ".jsonl"],
            "semgrep": [".json"]
        }

        uploaded_count = 0

        for tool_name, uploaded_file in uploaded_files.items():

            if uploaded_file is None or not uploaded_file.filename:
                continue

            original_name = secure_filename(
                uploaded_file.filename
            )

            file_extension = Path(original_name).suffix.lower()

            if file_extension not in allowed_formats[tool_name]:
                return jsonify({
                    "status": "error",
                    "message": (
                        f"Unsupported {tool_name} format. "
                        f"Allowed formats: "
                        f"{', '.join(allowed_formats[tool_name])}"
                    )
                }), 400

            if tool_name == "nmap":
                destination = INPUT_DIR / f"nmap_results{file_extension}"
                other_extension = ".json" if file_extension == ".xml" else ".xml"
                old_file = INPUT_DIR / f"nmap_results{other_extension}"

            elif tool_name == "nuclei":
                destination = INPUT_DIR / f"nuclei_results{file_extension}"
                other_extension = ".jsonl" if file_extension == ".json" else ".json"
                old_file = INPUT_DIR / f"nuclei_results{other_extension}"

            else:
                destination = INPUT_DIR / "semgrep_results.json"
                old_file = None

            if old_file and old_file.exists():
                old_file.unlink()

            uploaded_file.save(destination)
            uploaded_count += 1

        if uploaded_count == 0:
            return jsonify({
                "status": "error",
                "message": "Please select at least one report file."
            }), 400

        return jsonify({
            "status": "success",
            "message": f"{uploaded_count} report file(s) uploaded successfully.",
            "uploaded_count": uploaded_count
        })

    except Exception as error:
        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500


# ============================================================
# RUN SECURITY PIPELINE
# ============================================================

@app.route("/run-pipeline", methods=["GET", "POST"])
def run_pipeline_api():

    try:
        nmap_xml = INPUT_DIR / "nmap_results.xml"
        nmap_json = INPUT_DIR / "nmap_results.json"

        nuclei_json = INPUT_DIR / "nuclei_results.json"
        nuclei_jsonl = INPUT_DIR / "nuclei_results.jsonl"

        semgrep_path = INPUT_DIR / "semgrep_results.json"

        nmap_file = nmap_xml if nmap_xml.exists() else (
            nmap_json if nmap_json.exists() else None
        )

        nuclei_file = nuclei_jsonl if nuclei_jsonl.exists() else (
            nuclei_json if nuclei_json.exists() else None
        )

        semgrep_file = semgrep_path if semgrep_path.exists() else None

        # The current multi_loader expects all three input files.
        missing_tools = []

        if nmap_file is None:
            missing_tools.append("Nmap")

        if nuclei_file is None:
            missing_tools.append("Nuclei")

        if semgrep_file is None:
            missing_tools.append("Semgrep")

        if missing_tools:
            return jsonify({
                "status": "error",
                "message": (
                    "Please upload reports for all three tools before "
                    "running the multi-tool pipeline. Missing: "
                    + ", ".join(missing_tools)
                )
            }), 400

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
            "message": "Security finding pipeline executed successfully.",
            "original_count": result["original_count"],
            "duplicate_count": len(result["duplicate_pairs"]),
            "merged_count": len(result["merged_findings"]),
            "correlation_count": len(result["correlations"])
        })

    except Exception as error:
        app.logger.exception("Pipeline execution failed")

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500


# ============================================================
# DOWNLOAD JSON REPORT
# ============================================================

@app.route("/download-report")
def download_report():

    if not REPORT_FILE.exists():
        return jsonify({
            "status": "error",
            "message": "Security report not found. Run the pipeline first."
        }), 404

    return send_file(
        REPORT_FILE,
        as_attachment=True,
        download_name="security_report.json",
        mimetype="application/json"
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "status": "error",
        "message": "Upload too large. Maximum allowed size is 50 MB."
    }), 413


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)
