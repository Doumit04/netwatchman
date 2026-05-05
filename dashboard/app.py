import os
import sys
import json
import time
import uuid
import tempfile
import importlib
import traceback
import threading
from pathlib import Path

from flask import Flask, request, jsonify, render_template, Response, stream_with_context, abort
from dotenv import load_dotenv

load_dotenv()

# ── Path fix ──────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024   # 100 MB

# ── History + Export (new) ────────────────────────────────────────────────────
from db import init_db, save_scan, list_scans, get_scan, delete_scan, clear_all_scans
from export_utils import build_pdf, build_csv
init_db()   # create tables if they don't exist

# ── Detector registry ─────────────────────────────────────────────────────────
DETECTOR_NAMES = [
    "port_scan", "arp_spoof", "ssh_brute", "ftp_brute",
    "syn_flood", "icmp_flood", "dns_spoof", "cleartext_creds",
    "dir_traversal", "malicious_ip", "service_version", "sql_injection",
    "telnet", "xss", "suspicious_agents", "large_transfer",
]

def load_detectors():
    detectors = {}
    for name in DETECTOR_NAMES:
        try:
            mod = importlib.import_module(f"detectors.{name}")
            detectors[name] = mod
        except Exception as exc:
            app.logger.warning("Could not load detector '%s': %s", name, exc)
    return detectors

DETECTORS = load_detectors()

# ── Replay session store ──────────────────────────────────────────────────────
replay_sessions: dict = {}


# ── Helpers ───────────────────────────────────────────────────────────────────
def _allowed(filename: str) -> bool:
    return Path(filename).suffix.lower() in {".pcap", ".pcapng", ".cap"}

def _save_upload(file_storage) -> tuple[str, str]:
    ext = Path(file_storage.filename).suffix.lower()
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=ext)
    file_storage.save(tmp.name)
    tmp.close()
    return tmp.name, ext

def _alert_hash(alert: dict) -> str:
    key = json.dumps({k: alert.get(k) for k in sorted(alert)}, default=str, sort_keys=True)
    return str(hash(key))

def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"

def _export_meta(data: dict) -> dict:
    """Build scan-meta dict from a JSON export payload."""
    results = data.get("results", [])
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        s = (r.get("severity") or "info").lower()
        if s in c:
            c[s] += 1
    return {
        "source_name": data.get("source_name", "unknown"),
        "mode":        data.get("mode", "pcap"),
        "created_at":  data.get("created_at", ""),
        "total":         len(results),
        "total_packets": data.get("total_packets", 0),
        **c,
    }


# ── Full analysis ─────────────────────────────────────────────────────────────
def run_analysis(pcap_path: str) -> dict:
    from scapy.all import rdpcap
    from parser import parse_packet

    try:
        raw_packets = rdpcap(pcap_path)
        packets = [parse_packet(pkt) for pkt in raw_packets]
    except Exception as exc:
        return {"error": f"Failed to parse PCAP: {exc}", "alerts": []}

    alerts, detector_errors = [], []
    for name, mod in DETECTORS.items():
        try:
            findings = mod.detect(packets)
            if findings:
                for f in findings:
                    f.setdefault("detector", name)
                alerts.extend(findings)
        except Exception as exc:
            detector_errors.append({"detector": name, "error": str(exc)})
            app.logger.error("Detector '%s' raised:\n%s", name, traceback.format_exc())

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    alerts.sort(key=lambda a: sev_rank.get(str(a.get("severity", "info")).lower(), 99))

    return {
        "total_packets":   len(packets),
        "total_alerts":    len(alerts),
        "alerts":          alerts,
        "detector_errors": detector_errors,
    }


# ── Core routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html", detector_count=len(DETECTORS))


@app.route("/analyze", methods=["POST"])
def analyze():
    if "pcap" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    f = request.files["pcap"]
    if not f.filename or not _allowed(f.filename):
        return jsonify({"error": "Please upload a .pcap / .pcapng file."}), 400

    path, _ = _save_upload(f)
    try:
        result = run_analysis(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass

    if "error" not in result:
        # ── auto-save to history (new) ────────────────────────────────────────
        scan_id = save_scan(
            source_name=f.filename,
            mode="pcap",
            results=result.get("alerts", []),
            total_packets=result.get("total_packets", 0),
        )
        result["scan_id"] = scan_id

    return jsonify(result)


# ── Replay: upload ────────────────────────────────────────────────────────────
@app.route("/replay/upload", methods=["POST"])
def replay_upload():
    if "pcap" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    f = request.files["pcap"]
    if not f.filename or not _allowed(f.filename):
        return jsonify({"error": "Please upload a .pcap / .pcapng file."}), 400

    path, _ = _save_upload(f)
    try:
        from scapy.all import rdpcap
        total = len(rdpcap(path))
    except Exception as exc:
        os.unlink(path)
        return jsonify({"error": f"Could not read PCAP: {exc}"}), 400

    session_id = str(uuid.uuid4())
    replay_sessions[session_id] = {
        "path":        path,
        "stop":        threading.Event(),
        "source_name": f.filename,      # new – stored for DB save
        "all_alerts":  [],              # new – accumulated for DB save
    }
    return jsonify({"session_id": session_id, "total_packets": total})


# ── Replay: SSE stream ────────────────────────────────────────────────────────
@app.route("/replay/stream/<session_id>")
def replay_stream(session_id):
    session = replay_sessions.get(session_id)
    if not session:
        return jsonify({"error": "Session not found."}), 404

    @stream_with_context
    def generate():
        from scapy.all import rdpcap
        from parser import parse_packet

        stop_event: threading.Event = session["stop"]
        pcap_path:  str             = session["path"]

        try:
            raw_packets = rdpcap(pcap_path)
        except Exception as exc:
            yield _sse({"type": "error", "message": str(exc)})
            return

        total = len(raw_packets)
        yield _sse({"type": "start", "total": total})

        buffer:       list = []
        seen_hashes:  set  = set()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        speed = int(request.args.get("speed", 3))
        speed = max(1, min(5, speed))
        BATCH = {1: 5, 2: 10, 3: 20, 4: 40, 5: 80}[speed]
        DELAY = {1: 0.5, 2: 0.25, 3: 0.08, 4: 0.03, 5: 0.01}[speed]

        for i, raw_pkt in enumerate(raw_packets):
            if stop_event.is_set():
                yield _sse({"type": "stopped", "processed": i})
                return

            try:
                buffer.append(parse_packet(raw_pkt))
            except Exception:
                pass

            if (i + 1) % BATCH == 0 or i == total - 1:
                new_alerts = []

                for name, mod in DETECTORS.items():
                    try:
                        findings = mod.detect(buffer) or []
                        for alert in findings:
                            alert.setdefault("detector", name)
                            h = _alert_hash(alert)
                            if h not in seen_hashes:
                                seen_hashes.add(h)
                                new_alerts.append(alert)
                                sev = str(alert.get("severity", "info")).lower()
                                counts[sev if sev in counts else "info"] += 1
                    except Exception:
                        pass

                for alert in new_alerts:
                    session["all_alerts"].append(alert)   # accumulate for DB
                    yield _sse({"type": "alert", "alert": alert})

                pct = round((i + 1) / total * 100)
                yield _sse({
                    "type":    "progress",
                    "current": i + 1,
                    "total":   total,
                    "pct":     pct,
                    "counts":  counts,
                })
                time.sleep(DELAY)

        # ── save completed replay to history (new) ────────────────────────────
        scan_id = save_scan(
            source_name=session.get("source_name", "unknown"),
            mode="live",
            results=session.get("all_alerts", []),
            total_packets=total,
        )

        yield _sse({
            "type":         "done",
            "total_alerts": len(seen_hashes),
            "counts":       counts,
            "scan_id":      scan_id,    # new – sent to frontend
        })

        try:
            os.unlink(pcap_path)
        except OSError:
            pass
        replay_sessions.pop(session_id, None)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":       "keep-alive",
        },
    )


# ── Replay: stop ──────────────────────────────────────────────────────────────
@app.route("/replay/stop/<session_id>", methods=["POST"])
def replay_stop(session_id):
    session = replay_sessions.get(session_id)
    if session:
        session["stop"].set()
    return jsonify({"ok": True})


# ═════════════════════════════════════════════════════════════════════════════
#  SCAN HISTORY API  (new)
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/api/history")
def api_history_list():
    return jsonify(list_scans())


@app.route("/api/history/<int:scan_id>")
def api_history_get(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/history/<int:scan_id>", methods=["DELETE"])
def api_history_delete(scan_id):
    delete_scan(scan_id)
    return jsonify({"ok": True})


@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    n = clear_all_scans()
    return jsonify({"ok": True, "deleted": n})


# ═════════════════════════════════════════════════════════════════════════════
#  EXPORT ROUTES  (new)
# ═════════════════════════════════════════════════════════════════════════════

# ── Export in-flight / current results (frontend POSTs the data) ──────────────

@app.route("/export/pdf", methods=["POST"])
def export_pdf_live():
    data = request.get_json(force=True)
    meta = _export_meta(data)
    pdf  = build_pdf(meta, data.get("results", []))
    safe = meta["source_name"].replace(" ", "_")
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="netwatchman_{safe}.pdf"'},
    )


@app.route("/export/csv", methods=["POST"])
def export_csv_live():
    data    = request.get_json(force=True)
    meta    = _export_meta(data)
    csv_str = build_csv(meta, data.get("results", []))
    safe    = meta["source_name"].replace(" ", "_")
    return Response(
        csv_str.encode("utf-8"),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="netwatchman_{safe}.csv"'},
    )


# ── Export saved scan by DB id (simple GET, no body needed) ──────────────────

@app.route("/export/pdf/<int:scan_id>")
def export_pdf_saved(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    pdf  = build_pdf(scan, scan["results"])
    safe = scan["source_name"].replace(" ", "_")
    return Response(
        pdf,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="netwatchman_{safe}.pdf"'},
    )


@app.route("/export/csv/<int:scan_id>")
def export_csv_saved(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        abort(404)
    csv_str = build_csv(scan, scan["results"])
    safe    = scan["source_name"].replace(" ", "_")
    return Response(
        csv_str.encode("utf-8"),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="netwatchman_{safe}.csv"'},
    )


# ── Misc ──────────────────────────────────────────────────────────────────────

@app.route("/detectors")
def list_detectors():
    return jsonify({
        "loaded": list(DETECTORS.keys()),
        "failed": [n for n in DETECTOR_NAMES if n not in DETECTORS],
    })


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)