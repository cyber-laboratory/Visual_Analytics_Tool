from algorithm.dtw import full as _exact_dtw, squared_diff, euclidean

_MAX_DTW_CELLS = 4_000_000


_NUMERIC_COLS = {
    "len":         lambda pkt: int(pkt.get("info", {}).get("len") or 0),
    "src_port":    lambda pkt: int(pkt.get("info", {}).get("src_port") or 0),
    "dst_port":    lambda pkt: int(pkt.get("info", {}).get("dst_port") or 0),
    "payload_len": lambda pkt: int(pkt.get("info", {}).get("payload_len") or 0),
    "ttl":         lambda pkt: int(pkt.get("info", {}).get("ttl") or 0),
    "window":      lambda pkt: int(pkt.get("info", {}).get("window") or 0),
    "ulen":        lambda pkt: int(pkt.get("info", {}).get("ulen") or 0),
    "icmp_type":   lambda pkt: int(pkt.get("info", {}).get("type") or 0),
}

_NUMERIC_COL_SOURCE_KEYS = {
    "len": "len", "src_port": "src_port", "dst_port": "dst_port",
    "payload_len": "payload_len", "ttl": "ttl", "window": "window",
    "ulen": "ulen", "icmp_type": "type",
}


def _packet_vector(pkt, columns):
    return [_NUMERIC_COLS[c](pkt) for c in columns if c in _NUMERIC_COLS]


def available_dtw_columns(host_A_packets, host_B_packets):
    def has_data(packets, key):
        return any(pkt.get("info", {}).get(key) is not None for pkt in packets)

    return {
        col: has_data(host_A_packets, key) and has_data(host_B_packets, key)
        for col, key in _NUMERIC_COL_SOURCE_KEYS.items()
    }


def _get_field_str(pkt, field):
    top_level = {"src_ip": pkt.get("src_ip", ""), "dst_ip": pkt.get("dst_ip", ""), "protocol": pkt.get("protocol", "")}
    if field in top_level:
        return str(top_level[field])
    return str(pkt.get("info", {}).get(field, "") or "")


def _role_allows(roles, role):
    return not roles or role in roles


def _ip_matches(pkt, ip, roles):
    return (
        (_role_allows(roles, "src") and pkt.get("src_ip") == ip) or
        (_role_allows(roles, "dst") and pkt.get("dst_ip") == ip)
    )


def _filter_by_ip(packets, host_A_ip, host_B_ip, ip_mode, host_A_roles=None, host_B_roles=None):
    host_A_roles = host_A_roles or set()
    host_B_roles = host_B_roles or set()
    if ip_mode == "all" or (not host_A_ip and not host_B_ip):
        return packets
    if ip_mode == "single":
        ip = host_A_ip or host_B_ip
        roles = host_A_roles if host_A_ip else host_B_roles
        return [p for p in packets if _ip_matches(p, ip, roles)]
    if host_A_ip and host_B_ip:
        def matches(p):
            a_to_b = (
                _role_allows(host_A_roles, "src") and _role_allows(host_B_roles, "dst") and
                p.get("src_ip") == host_A_ip and p.get("dst_ip") == host_B_ip
            )
            b_to_a = (
                _role_allows(host_B_roles, "src") and _role_allows(host_A_roles, "dst") and
                p.get("src_ip") == host_B_ip and p.get("dst_ip") == host_A_ip
            )
            return a_to_b or b_to_a
        return [p for p in packets if matches(p)]
    ip = host_A_ip or host_B_ip
    roles = host_A_roles if host_A_ip else host_B_roles
    return [p for p in packets if _ip_matches(p, ip, roles)]


def _filter_nonzero_column(packets, col):
    key = _NUMERIC_COL_SOURCE_KEYS.get(col)
    fn = _NUMERIC_COLS.get(col)
    if not key or not fn:
        return packets
    return [p for p in packets if p.get("info", {}).get(key) is not None and fn(p) != 0]


def _matches_condition(pkt, cond):
    field = cond.get("field", "")
    op = cond.get("op", "=")
    val = str(cond.get("value", "")).lower()
    pkt_val = _get_field_str(pkt, field).lower()
    if op == "=":
        return pkt_val == val
    if op == "contains":
        return val in pkt_val
    if op == "!=":
        return pkt_val != val
    return True


def _filter_by_conditions(packets, conditions, logic):
    if not conditions:
        return packets
    if logic == "OR":
        return [p for p in packets if any(_matches_condition(p, c) for c in conditions)]
    return [p for p in packets if all(_matches_condition(p, c) for c in conditions)]


def _make_score_dist(threshold, match_cost, mismatch_scale):
    def dist(a, b):
        d = abs(a[0] - b[0]) if len(a) == 1 else euclidean(a, b)
        return match_cost if d <= threshold else d * mismatch_scale
    return dist


def _chunk_sequence(seq, window, stride):
    chunks = []
    for start in range(0, len(seq) - window + 1, stride):
        chunks.append((start, seq[start:start + window]))
    if not chunks:
        chunks.append((0, seq))
    return chunks


def build_dtw_alignment(
    host_A_packets,
    host_B_packets,
    algo="dtw",
    host_A_ip=None,
    host_B_ip=None,
    ip_mode="both",
    columns=None,
    conditions=None,
    filter_logic="AND",
    score_threshold=None,
    score_match=None,
    score_mismatch=None,
    window_size=None,
    stride=None,
    page=0,
    same_source=False,
    nonzero_column_only=False,
    host_A_roles=None,
    host_B_roles=None,
):
    host_A_packets = list(host_A_packets)
    host_B_packets = list(host_B_packets)
    host_A_roles = host_A_roles or set()
    host_B_roles = host_B_roles or set()

    if same_source and ip_mode == "both" and host_A_ip and host_B_ip:
        def _same_source_field(pkt, ip, roles):
            if roles == {"dst"}:
                return pkt.get("dst_ip") == ip
            if roles == {"src", "dst"}:
                return pkt.get("src_ip") == ip or pkt.get("dst_ip") == ip
            return pkt.get("src_ip") == ip
        host_A_packets = [p for p in host_A_packets if _same_source_field(p, host_A_ip, host_A_roles)]
        host_B_packets = [p for p in host_B_packets if _same_source_field(p, host_B_ip, host_B_roles)]
    else:
        host_A_packets = _filter_by_ip(host_A_packets, host_A_ip, host_B_ip, ip_mode, host_A_roles, host_B_roles)
        host_B_packets = _filter_by_ip(host_B_packets, host_A_ip, host_B_ip, ip_mode, host_A_roles, host_B_roles)

    host_A_packets = _filter_by_conditions(host_A_packets, conditions or [], filter_logic)
    host_B_packets = _filter_by_conditions(host_B_packets, conditions or [], filter_logic)

    if not host_A_packets or not host_B_packets:
        return None

    cols = columns if columns else ["len"]

    if nonzero_column_only:
        host_A_packets = _filter_nonzero_column(host_A_packets, cols[0])
        host_B_packets = _filter_nonzero_column(host_B_packets, cols[0])
        if not host_A_packets or not host_B_packets:
            return None

    host_A_seq = [_packet_vector(p, cols) for p in host_A_packets]
    host_B_seq = [_packet_vector(p, cols) for p in host_B_packets]

    host_A_seq = [v for v in host_A_seq if v]
    host_B_seq = [v for v in host_B_seq if v]

    if not host_A_seq or not host_B_seq:
        return None

    def _align_chunk(v_seq, a_seq, v_pkts, a_pkts, v_off, a_off):
        if score_threshold is not None:
            dist_fn = _make_score_dist(
                float(score_threshold),
                float(score_match if score_match is not None else 0),
                float(score_mismatch if score_mismatch is not None else 1),
            )
        else:
            dist_fn = squared_diff

        n, m = len(v_seq), len(a_seq)
        if n * m > _MAX_DTW_CELLS:
            raise ValueError(
                f"Exact DTW needs an {n}x{m} cost matrix ({n * m:,} cells) for "
                f"this window, which is too large to compute directly - set a "
                f"smaller sliding window size to break the capture into "
                f"chunks (currently {_MAX_DTW_CELLS:,} cells max)."
            )

        dist, raw_path, _cost_matrix = _exact_dtw(v_seq, a_seq, dist=dist_fn)
        pts, pth = [], []
        for vi, ai in raw_path:
            pts.append({
                "host_A_index":   vi + v_off,
                "host_B_index": ai + a_off,
                "distance": dist_fn(v_seq[vi], a_seq[ai]),
                "host_A_packet":   v_pkts[vi],
                "host_B_packet": a_pkts[ai],
            })
            pth.append([vi + v_off, ai + a_off])
        return dist, pts, pth

    if algo != "dtw":
        return None

    if window_size and window_size > 0:
        eff_stride = stride if stride and stride > 0 else max(1, window_size // 3)
        v_chunks = _chunk_sequence(host_A_seq, window_size, eff_stride)
        a_chunks = _chunk_sequence(host_B_seq, window_size, eff_stride)
        num_pages = max(len(v_chunks), len(a_chunks))
        page = max(0, min(page, num_pages - 1))

        if page < len(v_chunks):
            v_off, v_chunk = v_chunks[page]
            v_pkts_chunk = host_A_packets[v_off: v_off + len(v_chunk)]
        else:
            v_off, v_chunk, v_pkts_chunk = 0, host_A_seq, host_A_packets

        if page < len(a_chunks):
            a_off, a_chunk = a_chunks[page]
            a_pkts_chunk = host_B_packets[a_off: a_off + len(a_chunk)]
        else:
            a_off, a_chunk, a_pkts_chunk = 0, host_B_seq, host_B_packets

        distance, points, filtered_path = _align_chunk(v_chunk, a_chunk, v_pkts_chunk, a_pkts_chunk, 0, 0)
        out_host_A_seq, out_host_B_seq = v_chunk, a_chunk
    else:
        distance, points, filtered_path = _align_chunk(
            host_A_seq, host_B_seq, host_A_packets, host_B_packets, 0, 0
        )
        num_pages, page = 1, 0
        v_off = a_off = 0
        out_host_A_seq, out_host_B_seq = host_A_seq, host_B_seq

    return {
        "distance": distance,
        "host_A_count": len(out_host_A_seq),
        "host_B_count": len(out_host_B_seq),
        "points": points,
        "path": filtered_path,
        "columns": cols,
        "host_A_seq": out_host_A_seq,
        "host_B_seq": out_host_B_seq,
        "page": page,
        "num_pages": num_pages,
        "host_A_offset": v_off,
        "host_B_offset": a_off,
        "host_A_total": len(host_A_seq),
        "host_B_total": len(host_B_seq),
    }
