#!/usr/bin/env python3
"""冷蔵設備の管理画面（Danfoss StoreView・Copeland/Dixell XWEB ほか）の露出件数を定点計測する。

Shodan の count API（/shodan/host/count）だけを使い、検索に一致したサービスの件数と、
国・ポート・タグなどの集計値を JSON に保存する。

- IP アドレスやホスト名は取得しない。機器への接続や認証の試行もしない。
- count API は検索クレジットを消費しない。
- 件数は「実機の台数」ではない。おとり（ハニーポット）や同じ機器の複数ポートを含む。

期間の比較は「実行日から数えた同じ長さ」（直近7日・16日）で行う。
`after:29/10/2026` のように日付を固定すると、後日実行したときに期間が延びるうえ、
Shodan は同じ IP・ポートについて最新のバナーだけを保持するため、比較に使えない。

使い方:
    read -s SHODAN_API_KEY && export SHODAN_API_KEY
    python3 exposure_count.py
    python3 exposure_count.py --since 01/11/2026 --since 04/11/2026 -o result.json
"""
import argparse
import datetime
import json
import os
import sys
import time

try:
    import shodan
except ImportError:
    sys.exit("shodan ライブラリがありません。`pip install -r requirements.txt` を実行してください。")

# ---- 検索条件 ----
SV = 'http.title:"StoreView"'                # Danfoss StoreView（AK-SM 系の管理画面）
XW = 'http.title:"XWEB"'                     # Copeland / Dixell XWEB
NOISE = '-tag:cloud -tag:honeypot'           # Shodan がクラウド・おとりと判定したものを除外
NOIINET = '-org:"iiNet Connect Pty Ltd"'     # StoreView の大量の疑わしい応答（記事の前報 3.4.1 参照）

CTRY = [("country", 30)]
STD = [("country", 15), ("org", 15), ("port", 10), ("http.title", 15), ("version", 10), ("tag", 10)]
SSL = [("ssl.cert.fingerprint", 1000), ("ssl.cert.subject.cn", 30), ("port", 10), ("country", 15)]


def build_groups(r7, r16, since_list):
    """計測するクエリの一覧を返す。(名前, クエリ, ファセット) のタプル。"""
    g = [
        # A. 日付指定なし（Shodan が保持している全期間）
        ("sv_all",               f'{SV}', None),
        ("sv_clean_30d",         f'{SV} {NOISE}', None),
        ("sv_clean_noiinet_30d", f'{SV} {NOISE} {NOIINET}', CTRY),
        ("xweb_all",             f'{XW}', None),
        ("xweb_clean_30d",       f'{XW} {NOISE}', CTRY),
        ("iinet_30d",            f'{SV} org:"iiNet Connect Pty Ltd"', None),

        # B. 実行日から数えた直近7日・16日
        ("sv_clean_r16",         f'{SV} {NOISE} {r16}', None),
        ("sv_clean_r7",          f'{SV} {NOISE} {r7}', None),
        ("sv_noiinet_r16",       f'{SV} {NOISE} {NOIINET} {r16}', CTRY),
        ("sv_noiinet_r7",        f'{SV} {NOISE} {NOIINET} {r7}', CTRY),
        ("iinet_r16",            f'{SV} org:"iiNet Connect Pty Ltd" {r16}', None),
        ("iinet_r7",             f'{SV} org:"iiNet Connect Pty Ltd" {r7}', None),
        ("xweb_clean_r16",       f'{XW} {NOISE} {r16}', CTRY),
        ("xweb_clean_r7",        f'{XW} {NOISE} {r7}', CTRY),
    ]

    # C. 指定日以降（事案や警告の日付を基準に見る）
    for d in since_list:
        tag = d.replace("/", "")
        g += [
            (f"sv_noiinet_since{tag}", f'{SV} {NOISE} {NOIINET} after:{d}', CTRY),
            (f"xweb_clean_since{tag}", f'{XW} {NOISE} after:{d}', CTRY),
        ]

    g += [
        # D. 国別
        ("sv_fr_r7",             f'{SV} {NOISE} country:FR {r7}', None),
        ("sv_us_noiinet_30d",    f'{SV} {NOISE} {NOIINET} country:US', STD),
        ("sv_us_noiinet_r16",    f'{SV} {NOISE} {NOIINET} country:US {r16}', None),
        ("xweb_us_30d",          f'{XW} {NOISE} country:US', STD),
        ("xweb_us_r16",          f'{XW} {NOISE} country:US {r16}', None),
        ("xweb_be_r16",          f'{XW} {NOISE} country:BE {r16}', None),
        ("xweb_it_r7",           f'{XW} {NOISE} country:IT {r7}', None),
        ("xweb_il_r7",           f'{XW} {NOISE} country:IL {r7}', None),
        ("xweb_gb_r16",          f'{XW} {NOISE} country:GB {r16}', None),
        ("sv_gb_noiinet_r16",    f'{SV} {NOISE} {NOIINET} country:GB {r16}', None),

        # E. 製品の系統
        ("sv_old_title_r16",     f'http.title:"Danfoss StoreView" {NOISE} {NOIINET} {r16}', None),
        ("sv_web_title_r16",     f'http.title:"Danfoss - StoreView Web" {NOISE} {NOIINET} {r16}', None),
        ("xweb_evo_r16",         f'http.title:"XWEB EVO" {NOISE} {r16}', CTRY),
        ("xweb_pro_r16",         f'http.title:"XWEB PRO" {NOISE} {r16}', STD),
        ("xweb_plain_r16",       f'http.title:"XWEB" -http.title:"EVO" -http.title:"PRO" {NOISE} {r16}', CTRY),
        ("xweb_pro_30d",         f'http.title:"XWEB PRO" {NOISE}', STD),

        # F. TLS（おとりの影響を受けにくい指標）
        ("xweb_ssl_r16",         f'{XW} {NOISE} ssl:true {r16}', SSL),
        ("sv_ssl_r16",           f'{SV} {NOISE} {NOIINET} ssl:true {r16}', SSL),

        # G. その他の冷蔵関連の管理画面
        ("carel_pcoweb_r16",     f'http.title:"pCOWeb" {r16}', CTRY),
        ("eliwell_r16",          f'http.title:"Televis Go" {r16}', None),
    ]
    return g


def count(api, q, facets):
    """ファセットが大きすぎて失敗したら、件数を減らし、それでも駄目なら一つずつ外して再試行する。"""
    last = None
    tries = [facets, [(k, min(n, 100)) for k, n in facets]] if facets else [None]
    for fc in tries:
        try:
            return api.count(q, facets=fc), None
        except shodan.APIError as e:
            last = str(e)
            time.sleep(1.1)
    fc = list(facets or [])
    while fc:
        fc = fc[:-1]
        try:
            return api.count(q, facets=fc or None), f"facets reduced to {[k for k, _ in fc]} ({last})"
        except shodan.APIError as e:
            last = str(e)
            time.sleep(1.1)
    return None, last


def main():
    ap = argparse.ArgumentParser(description="冷蔵設備の管理画面の露出件数を Shodan の count API で計測する")
    ap.add_argument("--since", action="append", metavar="DD/MM/YYYY",
                    help="この日以降の件数も数える（複数指定可）。既定: 01/11/2026 と 04/11/2026")
    ap.add_argument("-o", "--output", help="出力ファイル名。既定: counts_YYYYmmdd_HHMMSS.json")
    args = ap.parse_args()

    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("環境変数 SHODAN_API_KEY が設定されていません。"
                 "`read -s SHODAN_API_KEY && export SHODAN_API_KEY` で設定してください。")
    api = shodan.Shodan(key)

    fn = args.output or f"counts_{time.strftime('%Y%m%d_%H%M%S')}.json"
    if os.path.exists(fn):
        sys.exit(f"{fn} は既に存在します。上書きしないよう終了しました。別の名前を -o で指定してください。")

    today = datetime.date.today()
    ago = lambda n: (today - datetime.timedelta(days=n)).strftime("%d/%m/%Y")
    r7, r16 = f"after:{ago(7)}", f"after:{ago(16)}"
    since_list = args.since or ["01/11/2026", "04/11/2026"]

    out = {
        "tool": "exposure_count",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "run_date": today.isoformat(),
        "windows": {"R7": r7, "R16": r16, "since": since_list},
        "results": {},
    }
    for name, q, facets in build_groups(r7, r16, since_list):
        t0 = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        r, note = count(api, q, facets)
        if r is None:
            out["results"][name] = {"query": q, "queried_at": t0, "error": note}
            print(f"{name:26s} ERROR {note}", flush=True)
        else:
            f = r.get("facets", {}) or {}
            summ = {}
            if "ssl.cert.fingerprint" in f:
                summ["ssl.cert.fingerprint_distinct"] = len(f["ssl.cert.fingerprint"])
                summ["ssl.cert.fingerprint_sum"] = sum(x["count"] for x in f["ssl.cert.fingerprint"])
                # フィンガープリントの値は保存せず、共有の分布だけを残す
                f["ssl.cert.fingerprint"] = sorted([x["count"] for x in f["ssl.cert.fingerprint"]], reverse=True)
            out["results"][name] = {"query": q, "queried_at": t0, "total": r["total"],
                                    "summary": summ, "facets": f, "note": note}
            us = next((x["count"] for x in f.get("country", []) if x["value"] == "US"), None)
            print(f"{name:26s} {r['total']:>7}" + (f"  US={us}" if us is not None else "")
                  + (f"  [{note}]" if note else ""), flush=True)
        time.sleep(1.1)

    out["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(fn, "w") as fp:
        json.dump(out, fp, ensure_ascii=False, indent=1)
    print(f"保存しました: {fn}")


if __name__ == "__main__":
    main()
