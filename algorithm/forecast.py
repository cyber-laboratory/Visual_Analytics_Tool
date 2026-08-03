import os
from itertools import chain

import numpy as np
import pandas as pd
from collections import defaultdict
from numpy.lib.stride_tricks import sliding_window_view

WINDOW = 10
BATCH  = 512
CHUNK = BATCH * 100

_scaler       = None
_feature_cols = None
_lstm_model   = None
_gru_model    = None
_lstm_predict = None
_gru_predict  = None
_loaded       = False
_load_error   = None

_DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')


def _ensure_loaded():
    global _scaler, _feature_cols, _lstm_model, _gru_model, _loaded, _load_error
    global _lstm_predict, _gru_predict
    if _loaded:
        return
    if _load_error:
        raise RuntimeError(_load_error)
    try:
        import joblib
        import tensorflow as tf
        from tensorflow import keras
        _scaler       = joblib.load(os.path.join(_DATA_DIR, 'scaler_forecast.pkl'))
        _feature_cols = joblib.load(os.path.join(_DATA_DIR, 'feature_cols_forecast.pkl'))
        _lstm_model   = keras.models.load_model(os.path.join(_DATA_DIR, 'best_lstm_fc.keras'))
        _gru_model    = keras.models.load_model(os.path.join(_DATA_DIR, 'best_gru_fc.keras'))
        _lstm_predict = tf.function(_lstm_model.call)
        _gru_predict  = tf.function(_gru_model.call)
        _loaded = True
    except Exception as e:
        _load_error = str(e)
        raise RuntimeError(f"Could not load forecast models: {e}")


def models_available():
    try:
        _ensure_loaded()
        return True, None
    except Exception as e:
        return False, str(e)


def preload():
    return models_available()


def _preprocess(df):
    df = df.copy()
    df['Timestamp'] = pd.to_numeric(df['Timestamp'], errors='coerce')
    if 'Label' in df.columns:
        df['Label'] = df['Label'].str.strip().str.lower()

    meta = df[['Src IP', 'Timestamp']].copy()
    if 'Label' in df.columns:
        meta['Label'] = df['Label']

    if 'Down/Up Ratio' in df.columns:
        df['Down/Up Ratio'] = pd.to_numeric(df['Down/Up Ratio'], errors='coerce').fillna(0)

    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    X = df[_feature_cols].values.astype(np.float32)
    X = _scaler.transform(X)
    return X, meta


def _forecast_per_host(df, predict_fn, window=WINDOW):
    X_scaled, meta = _preprocess(df)
    src_ips    = meta['Src IP'].values
    timestamps = meta['Timestamp'].values

    host_indices = defaultdict(list)
    for i, ip in enumerate(src_ips):
        host_indices[ip].append(i)

    pending_w, pending_start, pending_end, pending_kind, pending_hosts, pending_n = [], [], [], [], [], 0

    def _flush():
        nonlocal pending_w, pending_start, pending_end, pending_kind, pending_hosts, pending_n
        if pending_n == 0:
            return []
        batch  = pending_w[0]     if len(pending_w) == 1     else np.concatenate(pending_w, axis=0)
        starts = pending_start[0] if len(pending_start) == 1 else np.concatenate(pending_start)
        ends   = pending_end[0]   if len(pending_end) == 1   else np.concatenate(pending_end)
        kinds  = list(chain.from_iterable(pending_kind))
        hosts  = list(chain.from_iterable([h] * c for h, c in pending_hosts))

        preds = predict_fn(batch).numpy().flatten()
        rows = [
            {
                'src_ip':                   h,
                'window_start_ts':          float(s),
                'window_end_ts':             float(e),
                'predicted_malicious_rate':  float(p),
                'kind':                      k,
            }
            for h, s, e, p, k in zip(hosts, starts, ends, preds, kinds)
        ]
        pending_w, pending_start, pending_end, pending_kind, pending_hosts, pending_n = [], [], [], [], [], 0
        return rows

    for host in sorted(host_indices):
        indices = sorted(host_indices[host], key=lambda i: timestamps[i])
        host_X  = X_scaled[indices]
        host_ts = timestamps[indices]

        n_rows = len(host_X)
        if n_rows < window:
            continue

        windows = sliding_window_view(host_X, window, axis=0)
        windows = np.moveaxis(windows, -1, 1)
        n_windows = windows.shape[0]

        window_start_ts = host_ts[:n_windows]
        window_end_ts   = host_ts[window - 1: window - 1 + n_windows]

        offset = 0
        while offset < n_windows:
            take = min(n_windows - offset, CHUNK - pending_n)
            pending_w.append(np.ascontiguousarray(windows[offset:offset + take]))
            pending_start.append(window_start_ts[offset:offset + take])
            pending_end.append(window_end_ts[offset:offset + take])
            pending_kind.append(['window'] * take)
            pending_hosts.append((host, take))
            pending_n += take
            offset += take
            if pending_n >= CHUNK:
                yield from _flush()

        future_X  = host_X[-window:]
        future_ts = host_ts[-window:]
        chunk        = np.ascontiguousarray(future_X.reshape(1, window, future_X.shape[-1]))
        chunk_start_ts = future_ts[0:1]
        chunk_end_ts   = future_ts[window - 1:window]

        take = 1
        if pending_n + take > CHUNK:
            yield from _flush()
        pending_w.append(chunk)
        pending_start.append(chunk_start_ts)
        pending_end.append(chunk_end_ts)
        pending_kind.append(['future'])
        pending_hosts.append((host, take))
        pending_n += take
        if pending_n >= CHUNK:
            yield from _flush()

    yield from _flush()


def list_src_ips(filepath):
    ips = pd.read_csv(filepath, usecols=['Src IP'])['Src IP'].dropna().unique()
    return sorted(str(ip) for ip in ips)


_DISPLAY_COLS = {'Src IP', 'Dst IP', 'Timestamp'}

_last_csv_path = None
_last_csv_df = None


def _read_forecast_csv(filepath):
    global _last_csv_path, _last_csv_df
    usecols = sorted(set(_feature_cols) | _DISPLAY_COLS)
    df = pd.read_csv(filepath, usecols=usecols, low_memory=False)
    _last_csv_path = filepath
    _last_csv_df = df
    return df


def forecast_from_csv(filepath, model_name='lstm', src_ips=None):
    _ensure_loaded()
    df = _read_forecast_csv(filepath)
    if src_ips:
        df = df[df['Src IP'].isin(src_ips)]
    predict_fn = _lstm_predict if model_name == 'lstm' else _gru_predict
    yield from _forecast_per_host(df, predict_fn)


def get_window_rows(filepath, src_ip, start_ts, end_ts, limit=50):
    df = _last_csv_df if _last_csv_path == filepath else None
    if df is None:
        _ensure_loaded()
        df = _read_forecast_csv(filepath)

    mask = (df['Src IP'] == src_ip) & (df['Timestamp'] >= start_ts) & (df['Timestamp'] <= end_ts)
    records = df.loc[mask].head(limit).to_dict(orient='records')

    for row in records:
        for key, value in row.items():
            if isinstance(value, float) and (np.isnan(value) or np.isinf(value)):
                row[key] = None
    return records
