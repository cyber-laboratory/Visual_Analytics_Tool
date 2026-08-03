import csv
from collections import defaultdict
from pathlib import Path
import socket

import dpkt

TCP_FLAGS = "FSRPAU"

packet_store = {
    "host_A": [],
    "host_B": [],
}


def clear_role(role):
    packet_store[role].clear()


def fast_parse_grouped_by_second(file_path, role="host_A"):
    suffix = Path(file_path).suffix.lower()
    if suffix == ".csv":
        packets = parse_csv_capture(file_path)
    else:
        packets = parse_pcap_capture(file_path)

    buckets = defaultdict(list)
    for pkt in packets:
        buckets[int(pkt["timestamp"])].append(pkt)

    flat_packet_list = []
    for sec in sorted(buckets):
        flat_packet_list.extend(buckets[sec])

    packet_store[role] = flat_packet_list


def parse_pcap_capture(file_path):
    packets = []
    with open(file_path, "rb") as f:
        reader = _open_packet_reader(f)
        for pkt_id, (ts, buf) in enumerate(reader, start=1):
            pkt = parse_packet(buf, ts, pkt_id)
            if pkt:
                packets.append(pkt)
    return packets


def parse_csv_capture(file_path):
    packets = []
    with open(file_path, "r", newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for pkt_id, row in enumerate(reader, start=1):
            pkt = parse_csv_packet(row, pkt_id)
            if pkt:
                packets.append(pkt)
    return packets


def _open_packet_reader(file_handle):
    try:
        return dpkt.pcap.Reader(file_handle)
    except (ValueError, dpkt.NeedData, dpkt.UnpackError):
        file_handle.seek(0)
        return dpkt.pcapng.Reader(file_handle)


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_csv_packet(row, pkt_id):
    src_ip = row.get("ip.src") or ""
    dst_ip = row.get("ip.dst") or ""
    if not src_ip or not dst_ip:
        return None

    protocol = (row.get("_ws.col.protocol") or row.get("ip.proto") or "UNKNOWN").upper()
    timestamp = float(row.get("frame.time_epoch") or 0)
    src_port = _to_int(row.get("tcp.srcport") or row.get("udp.srcport"))
    dst_port = _to_int(row.get("tcp.dstport") or row.get("udp.dstport"))
    length = _to_int(row.get("tcp.len") or row.get("frame.len") or 0) or 0

    info = {
        "src_port": src_port,
        "dst_port": dst_port,
        "len": length,
        "flags": row.get("tcp.flags") or "",
    }

    ttl = _to_int(row.get("ip.ttl"))
    if ttl is not None:
        info["ttl"] = ttl

    window = _to_int(row.get("tcp.window_size_value") or row.get("tcp.window_size"))
    if window is not None:
        info["window"] = window

    seq = _to_int(row.get("tcp.seq") or row.get("tcp.seq_raw"))
    if seq is not None:
        info["seq"] = seq

    ack = _to_int(row.get("tcp.ack") or row.get("tcp.ack_raw"))
    if ack is not None:
        info["ack"] = ack

    ulen = _to_int(row.get("udp.length"))
    if ulen is not None:
        info["ulen"] = ulen

    payload_len = _to_int(row.get("tcp.payload.length") or row.get("data.len"))
    if payload_len is not None:
        info["payload_len"] = payload_len

    icmp_type = _to_int(row.get("icmp.type"))
    if icmp_type is not None:
        info["type"] = icmp_type

    icmp_code = _to_int(row.get("icmp.code"))
    if icmp_code is not None:
        info["code"] = icmp_code

    http_method = row.get("http.request.method") or ""
    http_uri = row.get("http.request.uri") or ""
    if http_method:
        info["http_method"] = http_method
    if http_uri:
        info["http_uri"] = http_uri

    conv_key = make_conversation_key(protocol, src_ip, src_port, dst_ip, dst_port)

    return {
        "id": pkt_id,
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "info": info,
        "flow_id": conv_key,
    }


def parse_packet(buf, ts, pkt_id):
    try:
        eth = dpkt.ethernet.Ethernet(memoryview(buf))
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            return None

        ip_data = ip.data
        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)
        protocol = type(ip_data).__name__.replace("IP", "").upper()

        info = {
            "src_port": getattr(ip_data, "sport", None),
            "dst_port": getattr(ip_data, "dport", None),
            "len": len(buf),
            "ttl": getattr(ip, "ttl", None),
        }

        match protocol:
            case "TCP":
                info = process_tcp(ip_data, info)
            case "UDP":
                info = process_udp(ip_data, info)
            case "ICMP":
                info = process_icmp(ip_data, info)
            case _:
                pass

        conv_key = make_conversation_key(
            protocol, src_ip, info["src_port"], dst_ip, info["dst_port"]
        )

        return {
            "id": pkt_id,
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "info": info,
            "flow_id": conv_key,
        }

    except Exception:
        return None


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def process_tcp(ip_data, info):
    flags = ip_data.flags
    info["flags"] = "".join(
        f
        for f, b in zip(
            TCP_FLAGS,
            [
                flags & dpkt.tcp.TH_FIN,
                flags & dpkt.tcp.TH_SYN,
                flags & dpkt.tcp.TH_RST,
                flags & dpkt.tcp.TH_PUSH,
                flags & dpkt.tcp.TH_ACK,
                flags & dpkt.tcp.TH_URG,
            ],
        )
        if b
    )
    info.update(
        {
            "window": ip_data.win,
            "seq": ip_data.seq,
            "ack": ip_data.ack,
        }
    )

    data = ip_data.data
    try:
        http_req = dpkt.http.Request(data)
        info.update(
            {
                "http_method": http_req.method,
                "http_host": http_req.headers.get("host", ""),
                "http_uri": http_req.uri,
            }
        )

        if http_req.method.upper() == "POST":
            raw_body = getattr(http_req, "body", b"")
            try:
                body_str = raw_body.decode("utf-8", errors="replace")
            except Exception:
                body_str = str(raw_body)
            info["http_body"] = body_str
    except (dpkt.UnpackError, dpkt.NeedData):
        try:
            http_res = dpkt.http.Response(data)
            info.update(
                {
                    "http_status": http_res.status,
                    "http_reason": http_res.reason,
                    "http_location": http_res.headers.get("location", ""),
                    "http_set_cookie": http_res.headers.get("set-cookie", ""),
                }
            )
        except (dpkt.UnpackError, dpkt.NeedData):
            pass
    raw = bytes(ip_data.data)
    info["payload_bytes"] = raw
    info["payload_len"] = len(raw)

    return info


def process_udp(ip_data, info):
    info["ulen"] = ip_data.ulen
    return info


def process_icmp(ip_data, info):
    info["type"] = ip_data.type
    info["code"] = ip_data.code
    return info


def make_conversation_key(protocol, src_ip, src_port, dst_ip, dst_port):
    left = (src_ip, -1 if src_port is None else src_port)
    right = (dst_ip, -1 if dst_port is None else dst_port)
    if left <= right:
        return f"{protocol}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    return f"{protocol}:{dst_ip}:{dst_port}-{src_ip}:{src_port}"
