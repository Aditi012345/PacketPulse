"""CICIDS2017-style flow features from a Scapy packet capture."""

import statistics

from scapy.layers.inet import IP, TCP, UDP

FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Bwd Segment Size",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# CICFlowMeter treats a gap > 1 second as idle (timestamps in microseconds).
IDLE_THRESHOLD_US = 1_000_000


def _mean(values):
    return float(statistics.mean(values)) if values else 0.0


def _std(values):
    return float(statistics.stdev(values)) if len(values) > 1 else 0.0


def _pkt_time_us(pkt):
    return float(pkt.time) * 1_000_000


def _ip_len(pkt):
    length = getattr(pkt[IP], "len", None)
    return int(length) if length else len(pkt[IP])


def _header_len(pkt):
    length = pkt[IP].ihl * 4
    if TCP in pkt:
        length += pkt[TCP].dataofs * 4
    elif UDP in pkt:
        length += 8
    return length


def _ports(pkt):
    if TCP in pkt:
        return pkt[TCP].sport, pkt[TCP].dport
    if UDP in pkt:
        return pkt[UDP].sport, pkt[UDP].dport
    return 0, 0


def _payload_len(pkt):
    if TCP in pkt:
        return len(bytes(pkt[TCP].payload))
    if UDP in pkt:
        return len(bytes(pkt[UDP].payload))
    return 0


def _tcp_flags(pkt):
    if TCP not in pkt:
        return 0, 0, 0, 0, 0
    flags = pkt[TCP].flags
    return (
        int(bool(flags & 0x01)),  # FIN
        int(bool(flags & 0x02)),  # SYN
        int(bool(flags & 0x08)),  # PSH
        int(bool(flags & 0x10)),  # ACK
        int(bool(flags & 0x20)),  # URG
    )


def _iats(timestamps):
    return [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]


def _active_idle(timestamps):
    if not timestamps:
        return [], []
    active = []
    idle = []
    active_start = timestamps[0]
    last = timestamps[0]
    for ts in timestamps[1:]:
        gap = ts - last
        if gap > IDLE_THRESHOLD_US:
            active.append(last - active_start)
            idle.append(gap)
            active_start = ts
        last = ts
    active.append(last - active_start)
    return active, idle


def _new_flow(pkt, dest_port):
    return {
        "dest_port": dest_port,
        "fwd_ts": [],
        "bwd_ts": [],
        "all_ts": [],
        "fwd_len": [],
        "bwd_len": [],
        "all_len": [],
        "fwd_hdr": [],
        "bwd_hdr": [],
        "fin": 0,
        "syn": 0,
        "psh": 0,
        "ack": 0,
        "urg": 0,
        "init_win_fwd": None,
        "init_win_bwd": None,
        "act_data_pkt_fwd": 0,
    }


def _add_packet(flow, pkt, direction):
    ts = _pkt_time_us(pkt)
    length = _ip_len(pkt)
    hdr = _header_len(pkt)
    fin, syn, psh, ack, urg = _tcp_flags(pkt)

    flow["all_ts"].append(ts)
    flow["all_len"].append(length)
    flow["fin"] += fin
    flow["syn"] += syn
    flow["psh"] += psh
    flow["ack"] += ack
    flow["urg"] += urg

    if direction == "fwd":
        flow["fwd_ts"].append(ts)
        flow["fwd_len"].append(length)
        flow["fwd_hdr"].append(hdr)
        if flow["init_win_fwd"] is None and TCP in pkt:
            flow["init_win_fwd"] = int(pkt[TCP].window)
        if _payload_len(pkt) > 0:
            flow["act_data_pkt_fwd"] += 1
    else:
        flow["bwd_ts"].append(ts)
        flow["bwd_len"].append(length)
        flow["bwd_hdr"].append(hdr)
        if flow["init_win_bwd"] is None and TCP in pkt:
            flow["init_win_bwd"] = int(pkt[TCP].window)


def _flow_row(flow):
    fwd_len = flow["fwd_len"]
    bwd_len = flow["bwd_len"]
    all_len = flow["all_len"]
    all_ts = sorted(flow["all_ts"])
    fwd_ts = sorted(flow["fwd_ts"])
    bwd_ts = sorted(flow["bwd_ts"])

    duration = (all_ts[-1] - all_ts[0]) if len(all_ts) > 1 else 0.0
    duration_s = duration / 1_000_000 if duration > 0 else 0.0
    total_bytes = sum(all_len)
    total_pkts = len(all_len)
    fwd_pkts = len(fwd_len)
    bwd_pkts = len(bwd_len)

    flow_iats = _iats(all_ts)
    fwd_iats = _iats(fwd_ts)
    bwd_iats = _iats(bwd_ts)
    active, idle = _active_idle(all_ts)
    pkt_std = _std(all_len)

    return {
        "Destination Port": flow["dest_port"],
        "Flow Duration": duration,
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Total Length of Fwd Packets": sum(fwd_len),
        "Total Length of Bwd Packets": sum(bwd_len),
        "Fwd Packet Length Max": max(fwd_len) if fwd_len else 0,
        "Fwd Packet Length Min": min(fwd_len) if fwd_len else 0,
        "Fwd Packet Length Mean": _mean(fwd_len),
        "Fwd Packet Length Std": _std(fwd_len),
        "Bwd Packet Length Max": max(bwd_len) if bwd_len else 0,
        "Bwd Packet Length Min": min(bwd_len) if bwd_len else 0,
        "Bwd Packet Length Std": _std(bwd_len),
        "Flow Bytes/s": (total_bytes / duration_s) if duration_s else 0.0,
        "Flow Packets/s": (total_pkts / duration_s) if duration_s else 0.0,
        "Flow IAT Mean": _mean(flow_iats),
        "Flow IAT Std": _std(flow_iats),
        "Flow IAT Max": max(flow_iats) if flow_iats else 0,
        "Flow IAT Min": min(flow_iats) if flow_iats else 0,
        "Fwd IAT Total": sum(fwd_iats) if fwd_iats else 0,
        "Fwd IAT Mean": _mean(fwd_iats),
        "Fwd IAT Std": _std(fwd_iats),
        "Fwd IAT Min": min(fwd_iats) if fwd_iats else 0,
        "Bwd IAT Total": sum(bwd_iats) if bwd_iats else 0,
        "Bwd IAT Mean": _mean(bwd_iats),
        "Bwd IAT Std": _std(bwd_iats),
        "Bwd IAT Max": max(bwd_iats) if bwd_iats else 0,
        "Bwd IAT Min": min(bwd_iats) if bwd_iats else 0,
        "Fwd Header Length": sum(flow["fwd_hdr"]),
        "Bwd Header Length": sum(flow["bwd_hdr"]),
        "Fwd Packets/s": (fwd_pkts / duration_s) if duration_s else 0.0,
        "Bwd Packets/s": (bwd_pkts / duration_s) if duration_s else 0.0,
        "Min Packet Length": min(all_len) if all_len else 0,
        "Max Packet Length": max(all_len) if all_len else 0,
        "Packet Length Mean": _mean(all_len),
        "Packet Length Std": pkt_std,
        "Packet Length Variance": pkt_std ** 2,
        "FIN Flag Count": flow["fin"],
        "SYN Flag Count": flow["syn"],
        "PSH Flag Count": flow["psh"],
        "ACK Flag Count": flow["ack"],
        "URG Flag Count": flow["urg"],
        "Down/Up Ratio": int(bwd_pkts / fwd_pkts) if fwd_pkts else 0,
        "Average Packet Size": _mean(all_len),
        "Avg Bwd Segment Size": _mean(bwd_len),
        "Init_Win_bytes_forward": flow["init_win_fwd"] if flow["init_win_fwd"] is not None else 0,
        "Init_Win_bytes_backward": flow["init_win_bwd"] if flow["init_win_bwd"] is not None else 0,
        "act_data_pkt_fwd": flow["act_data_pkt_fwd"],
        "min_seg_size_forward": min(flow["fwd_hdr"]) if flow["fwd_hdr"] else 0,
        "Active Mean": _mean(active),
        "Active Std": _std(active),
        "Active Max": max(active) if active else 0,
        "Active Min": min(active) if active else 0,
        "Idle Mean": _mean(idle),
        "Idle Std": _std(idle),
        "Idle Max": max(idle) if idle else 0,
        "Idle Min": min(idle) if idle else 0,
    }


def extract_flow_features(packets):
    """Group packets into bidirectional 5-tuple flows and compute CICIDS features."""
    flows = {}
    index = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src, dst = pkt[IP].src, pkt[IP].dst
        sport, dport = _ports(pkt)
        proto = pkt[IP].proto
        fwd_key = (src, dst, sport, dport, proto)
        rev_key = (dst, src, dport, sport, proto)

        if fwd_key in index:
            _add_packet(flows[index[fwd_key]], pkt, "fwd")
        elif rev_key in index:
            _add_packet(flows[index[rev_key]], pkt, "bwd")
        else:
            flows[fwd_key] = _new_flow(pkt, dport)
            index[fwd_key] = fwd_key
            _add_packet(flows[fwd_key], pkt, "fwd")

    return [_flow_row(flow) for flow in flows.values()]
