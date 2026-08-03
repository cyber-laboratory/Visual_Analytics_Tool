import argparse
import time
from pathlib import Path

import pandas as pd

_MICRO_COLS = [
    'flow_duration',
    'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
    'fwd_iat_tot', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
    'bwd_iat_tot', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
    'active_mean', 'active_max', 'idle_mean', 'idle_max',
]

_RENAME = {
    'src_ip': 'Src IP', 'dst_ip': 'Dst IP',
    'src_port': 'Src Port', 'dst_port': 'Dst Port', 'protocol': 'Protocol',
    'flow_duration': 'Flow Duration', 'tot_fwd_pkts': 'Tot Fwd Pkts', 'tot_bwd_pkts': 'Tot Bwd Pkts',
    'totlen_bwd_pkts': 'TotLen Bwd Pkts',
    'fwd_pkt_len_max': 'Fwd Pkt Len Max', 'fwd_pkt_len_min': 'Fwd Pkt Len Min',
    'fwd_pkt_len_mean': 'Fwd Pkt Len Mean', 'fwd_pkt_len_std': 'Fwd Pkt Len Std',
    'bwd_pkt_len_max': 'Bwd Pkt Len Max', 'bwd_pkt_len_min': 'Bwd Pkt Len Min',
    'bwd_pkt_len_mean': 'Bwd Pkt Len Mean', 'bwd_pkt_len_std': 'Bwd Pkt Len Std',
    'pkt_len_min': 'Pkt Len Min', 'pkt_len_max': 'Pkt Len Max',
    'pkt_len_mean': 'Pkt Len Mean', 'pkt_len_std': 'Pkt Len Std', 'pkt_len_var': 'Pkt Len Var',
    'flow_pkts_s': 'Flow Pkts/s', 'flow_byts_s': 'Flow Byts/s',
    'flow_iat_mean': 'Flow IAT Mean', 'flow_iat_std': 'Flow IAT Std',
    'flow_iat_max': 'Flow IAT Max', 'flow_iat_min': 'Flow IAT Min',
    'fwd_iat_tot': 'Fwd IAT Tot', 'fwd_iat_mean': 'Fwd IAT Mean',
    'fwd_iat_std': 'Fwd IAT Std', 'fwd_iat_max': 'Fwd IAT Max', 'fwd_iat_min': 'Fwd IAT Min',
    'bwd_iat_tot': 'Bwd IAT Tot', 'bwd_iat_mean': 'Bwd IAT Mean',
    'bwd_iat_std': 'Bwd IAT Std', 'bwd_iat_max': 'Bwd IAT Max', 'bwd_iat_min': 'Bwd IAT Min',
    'fwd_psh_flags': 'Fwd PSH Flags', 'bwd_psh_flags': 'Bwd PSH Flags',
    'fin_flag_cnt': 'FIN Flag Cnt', 'syn_flag_cnt': 'SYN Flag Cnt', 'rst_flag_cnt': 'RST Flag Cnt',
    'psh_flag_cnt': 'PSH Flag Cnt', 'ack_flag_cnt': 'ACK Flag Cnt', 'cwr_flag_count': 'CWE Flag Count',
    'down_up_ratio': 'Down/Up Ratio',
    'fwd_byts_b_avg': 'Fwd Byts/b Avg', 'bwd_byts_b_avg': 'Bwd Byts/b Avg',
    'fwd_pkts_b_avg': 'Fwd Pkts/b Avg', 'bwd_pkts_b_avg': 'Bwd Pkts/b Avg',
    'fwd_blk_rate_avg': 'Fwd Blk Rate Avg', 'bwd_blk_rate_avg': 'Bwd Blk Rate Avg',
    'fwd_header_len': 'Fwd Header Len', 'bwd_header_len': 'Bwd Header Len',
    'init_fwd_win_byts': 'Init Fwd Win Byts', 'init_bwd_win_byts': 'Init Bwd Win Byts',
    'active_mean': 'Active Mean', 'active_max': 'Active Max',
    'idle_mean': 'Idle Mean', 'idle_max': 'Idle Max',
}

_OUTPUT_COLS = ['Src IP', 'Dst IP', 'Timestamp'] + [
    v for k, v in _RENAME.items() if k not in ('src_ip', 'dst_ip')
]


def count_packets(pcap_path: Path) -> int:
    import dpkt

    n = 0
    with open(pcap_path, 'rb') as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except (ValueError, dpkt.NeedData, dpkt.UnpackError):
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)
        for _ in reader:
            n += 1
    return n


def _extract_flows(pcap_path: Path, raw_csv_path: Path, on_session=None) -> None:
    from scapy.sendrecv import AsyncSniffer
    from cicflowmeter.flow_session import FlowSession
    from cicflowmeter.sniffer import _start_periodic_gc

    session = FlowSession(output_mode='csv', output=str(raw_csv_path), fields=None, verbose=False)
    _start_periodic_gc(session)
    sniffer = AsyncSniffer(offline=str(pcap_path), prn=session.process, store=False)

    if on_session:
        on_session(session)
    sniffer.start()
    try:
        sniffer.join()
    finally:
        if hasattr(session, '_gc_stop'):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        sniffer.join()
        session.flush_flows()


def convert(pcap_path: Path, output_csv: Path, on_session=None) -> int:
    raw_csv = output_csv.with_suffix('.raw.csv')
    _extract_flows(pcap_path, raw_csv, on_session=on_session)

    df = pd.read_csv(raw_csv)
    raw_csv.unlink(missing_ok=True)

    for col in _MICRO_COLS:
        df[col] = df[col] * 1_000_000

    df['Timestamp'] = (pd.to_datetime(df['timestamp']) - pd.Timestamp('1970-01-01')) / pd.Timedelta(seconds=1)
    df = df.rename(columns=_RENAME)
    df[_OUTPUT_COLS].to_csv(output_csv, index=False)
    return len(df)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap', type=Path)
    parser.add_argument('output_csv', type=Path)
    args = parser.parse_args()

    start = time.time()
    n = convert(args.pcap, args.output_csv)
    print(f'Wrote {n} flows to {args.output_csv} in {time.time() - start:.1f}s')


if __name__ == '__main__':
    main()
