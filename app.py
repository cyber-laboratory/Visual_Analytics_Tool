import functools
import json
import math
import threading
import time
import uuid
from pathlib import Path

from flask import Flask, request, jsonify, render_template, send_from_directory, Response, stream_with_context
from backend.packet_parser import (
    fast_parse_grouped_by_second,
    packet_store,
    clear_role,
)
from backend.dtw_service import build_dtw_alignment, available_dtw_columns
import os

try:
    import orjson
    def _dump_row(obj):
        return orjson.dumps(obj).decode("utf-8")
except ImportError:
    def _dump_row(obj):
        return json.dumps(obj)

try:
    from algorithm.forecast import forecast_from_csv, models_available, preload as _preload_forecast, list_src_ips, get_window_rows
    _FORECAST_AVAILABLE = True
    ok, err = _preload_forecast()
    if not ok:
        print(f"[forecast] Models not loaded at startup: {err}")
except Exception as _e:
    _FORECAST_AVAILABLE = False
    print(f"[forecast] Module unavailable: {_e}")

try:
    import cicflowmeter
    _PCAP_CONVERT_AVAILABLE = True
except Exception as _e:
    _PCAP_CONVERT_AVAILABLE = False
    print(f"[forecast] PCAP-to-forecast-CSV conversion unavailable: {_e}")

_FORECAST_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_CAPTURE_SUFFIXES = {".pcap", ".pcapng", ".csv"}


def serialize_packet(pkt):
    if isinstance(pkt, dict):
        return {k: serialize_packet(v) for k, v in pkt.items()}
    elif isinstance(pkt, list):
        return [serialize_packet(i) for i in pkt]
    elif isinstance(pkt, bytes):
        return pkt.hex()
    else:
        return pkt


def _serialize_packet_summary(pkt):
    data = serialize_packet(pkt)
    info = data.get("info")
    if isinstance(info, dict) and "payload_bytes" in info:
        data = {**data, "info": {k: v for k, v in info.items() if k != "payload_bytes"}}
    return data


def allowed_capture(filename):
    return Path(filename).suffix.lower() in ALLOWED_CAPTURE_SUFFIXES


uploaded_capture_path = {"host_A": None, "host_B": None}


def save_capture(file_storage, role):
    filename = file_storage.filename
    path = os.path.join(app.config["UPLOAD_FOLDER"], f"{role}_{filename}")
    file_storage.save(path)
    uploaded_capture_path[role] = path
    return path


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload_pcap():
    clear_role("host_A")
    clear_role("host_B")

    files = request.files
    uploaded_files = {}
    for role in ["host_A", "host_B"]:
        file = files.get(role)
        if file:
            if not allowed_capture(file.filename):
                return jsonify({"error": f"Invalid {role} file type"}), 400
            uploaded_files[role] = file

    if not uploaded_files:
        return jsonify({"error": "Upload at least one PCAP, PCAPNG, or CSV file"}), 400

    if len(uploaded_files) == 1:
        role, file = next(iter(uploaded_files.items()))
        path = save_capture(file, role)
        fast_parse_grouped_by_second(path, role=role)

        other_role = "host_B" if role == "host_A" else "host_A"
        fast_parse_grouped_by_second(path, role=other_role)
        uploaded_capture_path[other_role] = path
    else:
        for role, file in uploaded_files.items():
            path = save_capture(file, role)
            fast_parse_grouped_by_second(path, role=role)

    all_packets = packet_store["host_A"] + packet_store["host_B"]
    unique_ips = sorted(set(
        ip for p in all_packets
        for ip in [p.get("src_ip"), p.get("dst_ip")]
        if ip
    ))

    return jsonify(
        {
            "message": "Capture data parsed",
            "host_A_count": len(packet_store["host_A"]),
            "host_B_count": len(packet_store["host_B"]),
            "unique_ips": unique_ips,
            "dtw_columns_available": available_dtw_columns(packet_store["host_A"], packet_store["host_B"]),
        }
    )


def _parse_dtw_params():
    host_A_ip = request.args.get("host_A_ip") or None
    host_B_ip = request.args.get("host_B_ip") or None
    ip_mode = request.args.get("ip_mode", "both")
    columns_str = request.args.get("columns", "len")
    columns = [c.strip() for c in columns_str.split(",") if c.strip()]
    filter_logic = request.args.get("filter_logic", "AND")
    conditions_str = request.args.get("conditions", "[]")
    try:
        conditions = json.loads(conditions_str)
    except (ValueError, TypeError):
        conditions = []
    score_threshold = request.args.get("score_threshold", type=float)
    score_match = request.args.get("score_match", type=float)
    score_mismatch = request.args.get("score_mismatch", type=float)
    algo = request.args.get("algo", "dtw")
    window_size = request.args.get("window_size", type=int)
    stride = request.args.get("stride", type=int)
    page = request.args.get("page", default=0, type=int)
    nonzero_column_only = request.args.get("nonzero_column_only", "0") in ("1", "true", "True")

    def _roles(src_arg, dst_arg):
        roles = set()
        if request.args.get(src_arg, "0") in ("1", "true", "True"):
            roles.add("src")
        if request.args.get(dst_arg, "0") in ("1", "true", "True"):
            roles.add("dst")
        return roles
    host_A_roles = _roles("host_A_src", "host_A_dst")
    host_B_roles = _roles("host_B_src", "host_B_dst")
    same_source = (
        uploaded_capture_path["host_A"] is not None
        and uploaded_capture_path["host_A"] == uploaded_capture_path["host_B"]
    )
    return dict(
        host_A_ip=host_A_ip,
        host_B_ip=host_B_ip,
        ip_mode=ip_mode,
        columns=columns,
        filter_logic=filter_logic,
        conditions=conditions,
        score_threshold=score_threshold,
        score_match=score_match,
        score_mismatch=score_mismatch,
        algo=algo,
        window_size=window_size,
        stride=stride,
        page=page,
        same_source=same_source,
        nonzero_column_only=nonzero_column_only,
        host_A_roles=host_A_roles,
        host_B_roles=host_B_roles,
    )


def _serialize_dtw_points(points):
    return [
        {
            "host_A_index": point["host_A_index"],
            "host_B_index": point["host_B_index"],
            "distance": point["distance"],
            "host_A_packet": _serialize_packet_summary(point["host_A_packet"]),
            "host_B_packet": _serialize_packet_summary(point["host_B_packet"]),
        }
        for point in points
    ]


@app.route("/dtw-data")
def dtw_data():
    params = _parse_dtw_params()
    alignment = build_dtw_alignment(packet_store["host_A"], packet_store["host_B"], **params)

    if not alignment:
        return jsonify({"error": "Upload packet data first"}), 400

    return jsonify(
        {
            "distance": alignment["distance"],
            "host_A_count": alignment["host_A_count"],
            "host_B_count": alignment["host_B_count"],
            "points": _serialize_dtw_points(alignment["points"]),
        }
    )


_dtw_jobs = {}
_dtw_jobs_lock = threading.Lock()

_DTW_JOB_TTL_S = 15 * 60


def _sweep_dtw_jobs():
    while True:
        time.sleep(60)
        now = time.time()
        with _dtw_jobs_lock:
            expired = [
                jid for jid, job in _dtw_jobs.items()
                if job['status'] in ('done', 'error')
                and now - (job.get('last_served_at') or job['created_at']) > _DTW_JOB_TTL_S
            ]
            for jid in expired:
                del _dtw_jobs[jid]


threading.Thread(target=_sweep_dtw_jobs, daemon=True).start()


def _run_dtw_job(job_id, params, host_A_packets, host_B_packets):
    job = _dtw_jobs[job_id]
    try:
        job['status'] = 'computing'
        alignment = build_dtw_alignment(host_A_packets, host_B_packets, **params)
        if not alignment:
            job['status'] = 'error'
            job['error'] = 'Upload packet data first'
            return

        job['result'] = {
            "host_A_seq": alignment.get("host_A_seq", []),
            "host_B_seq": alignment.get("host_B_seq", []),
            "columns": alignment.get("columns", []),
            "path": alignment.get("path", []),
            "distance": alignment.get("distance", 0),
            "points": _serialize_dtw_points(alignment.get("points", [])),
            "page": alignment.get("page", 0),
            "num_pages": alignment.get("num_pages", 1),
            "host_A_offset": alignment.get("host_A_offset", 0),
            "host_B_offset": alignment.get("host_B_offset", 0),
            "host_A_total": alignment.get("host_A_total", 0),
            "host_B_total": alignment.get("host_B_total", 0),
        }
        job['status'] = 'done'
    except Exception as e:
        job['status'] = 'error'
        job['error'] = str(e)


@app.route("/dtw-warping", methods=["POST"])
def dtw_warping_start():
    params = _parse_dtw_params()
    job_id = uuid.uuid4().hex
    with _dtw_jobs_lock:
        _dtw_jobs[job_id] = {
            'status': 'queued', 'result': None, 'error': None,
            'last_served_at': None, 'created_at': time.time(),
        }

    threading.Thread(
        target=_run_dtw_job,
        args=(job_id, params, packet_store["host_A"], packet_store["host_B"]),
        daemon=True,
    ).start()
    return jsonify({"job_id": job_id})


@app.route("/dtw-warping/status")
def dtw_warping_status():
    job_id = request.args.get("job_id") or ""
    with _dtw_jobs_lock:
        job = _dtw_jobs.get(job_id)
        if not job:
            return jsonify({"error": "Unknown or expired job_id"}), 404
        if job["status"] in ("done", "error"):
            job["last_served_at"] = time.time()
        status, error, result = job["status"], job.get("error"), job.get("result")

    return jsonify({
        "status": status,
        "error": error,
        "result": result,
    })


@app.route("/packets/<role>/density")
def packets_density(role):
    if role not in packet_store:
        return jsonify({"error": "Invalid role"}), 400

    interval = request.args.get("interval", default=1, type=float) or 1
    buckets = {}
    for pkt in packet_store[role]:
        bucket = math.floor(pkt.get("timestamp", 0) / interval) * interval
        buckets[bucket] = buckets.get(bucket, 0) + 1

    return jsonify(
        {"points": [{"t": t, "count": c} for t, c in sorted(buckets.items())]}
    )


@app.route("/packets/field-values")
def packets_field_values():
    field = request.args.get("field")
    if not field:
        return jsonify({"values": []})

    top_level_fields = {"src_ip", "dst_ip", "protocol"}
    seen = set()
    for pkt in packet_store["host_A"] + packet_store["host_B"]:
        val = pkt.get(field) if field in top_level_fields else (pkt.get("info") or {}).get(field)
        if val is not None and val != "":
            seen.add(str(val))

    def _cmp(a, b):
        try:
            na, nb = float(a), float(b)
            return -1 if na < nb else (1 if na > nb else 0)
        except ValueError:
            return -1 if a < b else (1 if a > b else 0)

    values = sorted(seen, key=functools.cmp_to_key(_cmp))
    return jsonify({"values": values})


@app.route("/clear", methods=["POST"])
def clear_data():
    clear_role("host_A")
    clear_role("host_B")
    return jsonify({"message": "Cleared"})


@app.route("/uploads/<path:filename>")
def serve_uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route('/forecast/files')
def forecast_files():
    if not os.path.isdir(_FORECAST_DATA_DIR):
        files = []
    else:
        names = sorted(
            f for f in os.listdir(_FORECAST_DATA_DIR)
            if f.lower().endswith('.csv') and not f.lower().endswith('.raw.csv')
        )
        files = [
            {'name': n, 'size': os.path.getsize(os.path.join(_FORECAST_DATA_DIR, n))}
            for n in names
        ]

    def _upload_info(role, path):
        if not path or not os.path.isfile(path):
            return {'available': False, 'name': None, 'size': None}
        return {
            'available': Path(path).suffix.lower() in ('.pcap', '.pcapng'),
            'name': os.path.basename(path),
            'size': os.path.getsize(path),
        }

    return jsonify({
        'files': files,
        'models_ready': _FORECAST_AVAILABLE,
        'pcap_convert_ready': _PCAP_CONVERT_AVAILABLE,
        'convertible_uploads': {
            role: _upload_info(role, path)
            for role, path in uploaded_capture_path.items()
        },
    })


_convert_jobs = {}
_convert_jobs_lock = threading.Lock()

_CONVERT_STALL_TIMEOUT_S = 600


def _run_conversion_job(job_id, path, out_path, out_name):
    job = _convert_jobs[job_id]
    try:
        from algorithm.pcap_to_forecast_csv import convert as _convert_pcap, count_packets
        job['total'] = count_packets(Path(path))
        job['status'] = 'converting'

        stop_polling = threading.Event()
        last_progress = {'count': 0, 'at': time.time()}

        def _on_session(session):
            def _poll():
                while not stop_polling.is_set():
                    processed = getattr(session, 'packets_count', job['processed'])
                    if processed != last_progress['count']:
                        last_progress['count'] = processed
                        last_progress['at'] = time.time()
                    job['processed'] = processed
                    stop_polling.wait(0.5)
            threading.Thread(target=_poll, daemon=True).start()

            def _watchdog():
                while not stop_polling.wait(5):
                    if time.time() - last_progress['at'] > _CONVERT_STALL_TIMEOUT_S:
                        job['status'] = 'error'
                        job['error'] = (
                            f"Conversion stalled - no progress in {_CONVERT_STALL_TIMEOUT_S // 60} "
                            f"minutes (stuck at {last_progress['count']}/{job['total']} packets). "
                            "Try re-uploading the capture."
                        )
                        stop_polling.set()
                        return
            threading.Thread(target=_watchdog, daemon=True).start()

        try:
            n = _convert_pcap(Path(path), Path(out_path), on_session=_on_session)
        finally:
            stop_polling.set()

        if job['status'] == 'error':
            return

        job['processed'] = job['total']
        job['status'] = 'done'
        job['result'] = {'filename': out_name, 'rows': n}
    except Exception as e:
        job['status'] = 'error'
        job['error'] = str(e)


@app.route('/forecast/convert-upload', methods=['POST'])
def forecast_convert_upload():
    if not _PCAP_CONVERT_AVAILABLE:
        return jsonify({'error': 'PCAP-to-forecast conversion unavailable (cicflowmeter not installed on the server)'}), 503

    data = request.get_json(silent=True) or {}
    role = data.get('role')
    if role not in ('host_A', 'host_B'):
        return jsonify({'error': 'role must be "host_A" or "host_B"'}), 400

    path = uploaded_capture_path.get(role)
    if not path or not os.path.isfile(path):
        return jsonify({'error': f'No {role} capture uploaded yet'}), 400

    suffix = Path(path).suffix.lower()
    if suffix not in ('.pcap', '.pcapng'):
        return jsonify({
            'error': f'The uploaded {role} file is a CSV, not a PCAP - flow-feature '
                     f'extraction needs the original packet capture.'
        }), 400

    stem = Path(path).stem
    prefix = f'{role}_'
    if stem.startswith(prefix):
        stem = stem[len(prefix):]
    out_name = f'{stem}_{int(time.time())}.csv'
    out_path = os.path.join(_FORECAST_DATA_DIR, out_name)
    os.makedirs(_FORECAST_DATA_DIR, exist_ok=True)

    job_id = uuid.uuid4().hex
    with _convert_jobs_lock:
        _convert_jobs[job_id] = {'status': 'counting', 'total': None, 'processed': 0, 'result': None, 'error': None}

    threading.Thread(target=_run_conversion_job, args=(job_id, path, out_path, out_name), daemon=True).start()
    return jsonify({'job_id': job_id})


@app.route('/forecast/convert-status')
def forecast_convert_status():
    job_id = request.args.get('job_id') or ''
    with _convert_jobs_lock:
        job = _convert_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Unknown or expired job_id'}), 404

    percent = round(job['processed'] / job['total'] * 100) if job['total'] else None
    return jsonify({
        'status': job['status'],
        'processed': job['processed'],
        'total': job['total'],
        'percent': min(100, percent) if percent is not None else None,
        'result': job['result'],
        'error': job['error'],
    })


def _forecast_csv_path(filename):
    if not filename:
        return None, ('No filename provided', 400)
    if Path(filename).suffix.lower() != '.csv':
        return None, ('File must be a .csv', 400)
    safe_name = os.path.basename(filename)
    path = os.path.join(_FORECAST_DATA_DIR, safe_name)
    if not os.path.isfile(path):
        return None, (f'File not found: {safe_name}', 404)
    return path, None


@app.route('/forecast/ips')
def forecast_ips():
    filename = (request.args.get('filename') or '').strip()
    path, error = _forecast_csv_path(filename)
    if error:
        return jsonify({'error': error[0]}), error[1]
    try:
        ips = list_src_ips(path)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'ips': ips})


@app.route('/forecast/window')
def forecast_window():
    filename = (request.args.get('filename') or '').strip()
    src_ip = request.args.get('src_ip') or ''
    start_ts = request.args.get('start_ts', type=float)
    end_ts = request.args.get('end_ts', type=float)

    path, error = _forecast_csv_path(filename)
    if error:
        return jsonify({'error': error[0]}), error[1]
    if not src_ip or start_ts is None or end_ts is None:
        return jsonify({'error': 'src_ip, start_ts and end_ts are required'}), 400

    try:
        rows = get_window_rows(path, src_ip, start_ts, end_ts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return jsonify({'rows': rows})


@app.route('/forecast', methods=['POST'])
def run_forecast():
    if not _FORECAST_AVAILABLE:
        return jsonify({'error': 'Forecast module unavailable (check TensorFlow/joblib install)'}), 503

    available, err = models_available()
    if not available:
        return jsonify({'error': f'Models not loaded: {err}'}), 503

    data = request.get_json(silent=True) or {}
    filename = data.get('filename', '').strip()
    model_name = data.get('model_name', 'lstm')
    src_ips = data.get('src_ips') or None

    path, error = _forecast_csv_path(filename)
    if error:
        return jsonify({'error': error[0]}), error[1]

    result_iter = forecast_from_csv(path, model_name, src_ips=src_ips)

    try:
        first = next(result_iter, None)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    def generate():
        count = 0
        if first is not None:
            yield _dump_row(first) + '\n'
            count = 1
        for row in result_iter:
            yield _dump_row(row) + '\n'
            count += 1
        yield _dump_row({'type': 'done', 'count': count}) + '\n'

    return Response(stream_with_context(generate()), mimetype='application/x-ndjson')


if __name__ == "__main__":
    app.run(debug=True, port=5001)
