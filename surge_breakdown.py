#!/usr/bin/env python3
"""Danfoss StoreView の件数が急増したとき、その内訳を調べる。

指定した国について、基準日「以降」と「以前」の件数を並べ、事業者・ASN・ポート・
画面（HTML）・TLS の偏りを集計する。少数の事業者やポート、同じ HTML に集中していれば、
実機ではなく、実機の画面を複製したおとり（ハニーポット）である可能性が高い。

- Shodan の count API だけを使う（検索クレジットを消費しない）。
- IP アドレス・ホスト名・証明書のサブジェクト名は取得しない。機器への接続もしない。
- 判定は集計値からの推定であり、個々のホストを確認したものではない。

使い方:
    read -s SHODAN_API_KEY && export SHODAN_API_KEY
    python3 surge_breakdown.py
    python3 surge_breakdown.py --countries NL,HK --controls FR,US --split-date 04/11/2026

特定の HTML ハッシュの件数も数えたい場合は、環境変数 SV_HTML_HASH に値を設定する。
"""
import argparse
import json
import os
import sys
import time

try:
    import shodan
except ImportError:
    sys.exit("shodan ライブラリがありません。`pip install -r requirements.txt` を実行してください。")

SV = 'http.title:"StoreView"'
NOISE = '-tag:cloud -tag:honeypot'
NOIINET = '-org:"iiNet Connect Pty Ltd"'

F = [("org", 20), ("asn", 20), ("port", 15), ("http.html_hash", 15), ("http.favicon.hash", 10),
     ("http.title", 10), ("version", 10), ("tag", 10), ("ssl.version", 5)]
SMALL = [("org", 10), ("port", 10), ("http.html_hash", 10)]


def build_groups(suspect, control, split, html_hash):
    new, old = f"after:{split}", f"before:{split}"
    g = []
    for c in suspect + control:
        g += [
            (f"{c}_new",          f'{SV} {NOISE} {NOIINET} country:{c} {new}', F),
            (f"{c}_old",          f'{SV} {NOISE} {NOIINET} country:{c} {old}', F),
            (f"{c}_new_tls",      f'{SV} {NOISE} {NOIINET} country:{c} ssl:true {new}', None),
            # Shodan は (tag:a OR tag:b) を受け付けないため、タグごとに数える
            (f"{c}_new_honeypot", f'{SV} {NOIINET} country:{c} tag:honeypot {new}', SMALL),
            (f"{c}_new_cloud",    f'{SV} {NOIINET} country:{c} tag:cloud {new}', SMALL),
        ]
        if html_hash:
            g.append((f"{c}_new_hash", f'{SV} {NOISE} {NOIINET} country:{c} http.html_hash:{html_hash} {new}', None))
    g += [
        ("all_new",          f'{SV} {NOISE} {NOIINET} {new}', F),
        ("all_new_ex_suspect", f'{SV} {NOISE} {NOIINET} {new} ' + " ".join(f"-country:{c}" for c in suspect), F),
        ("all_new_honeypot", f'{SV} tag:honeypot {new}', [("country", 15)]),
        ("all_new_cloud",    f'{SV} tag:cloud {new}', [("country", 15)]),
    ]
    if html_hash:
        g.append(("all_new_hash", f'{SV} {NOISE} {NOIINET} http.html_hash:{html_hash} {new}',
                  [("country", 15), ("org", 15)]))
    return g


def count(api, q, facets):
    last = None
    tries = [facets, [(k, min(n, 10)) for k, n in facets]] if facets else [None]
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


def top_share(facet_list, n=3):
    """上位 n 個が全体に占める割合。1 に近いほど少数に集中している。"""
    tot = sum(x["count"] for x in facet_list) if facet_list else 0
    top = sum(x["count"] for x in facet_list[:n]) if facet_list else 0
    return round(top / tot, 3) if tot else None


def main():
    ap = argparse.ArgumentParser(description="StoreView の件数の急増分を、事業者・ポート・HTML・TLS の偏りで調べる")
    ap.add_argument("--countries", default="NL,CN,HK,LV,SG", help="調べる国（既定: NL,CN,HK,LV,SG）")
    ap.add_argument("--controls", default="FR,US", help="比較対照の国（既定: FR,US）")
    ap.add_argument("--split-date", default="04/11/2026", metavar="DD/MM/YYYY",
                    help="この日の前後で比べる（既定: 04/11/2026）")
    ap.add_argument("-o", "--output", help="出力ファイル名。既定: breakdown_YYYYmmdd_HHMMSS.json")
    args = ap.parse_args()

    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        sys.exit("環境変数 SHODAN_API_KEY が設定されていません。"
                 "`read -s SHODAN_API_KEY && export SHODAN_API_KEY` で設定してください。")
    api = shodan.Shodan(key)

    fn = args.output or f"breakdown_{time.strftime('%Y%m%d_%H%M%S')}.json"
    if os.path.exists(fn):
        sys.exit(f"{fn} は既に存在します。上書きしないよう終了しました。別の名前を -o で指定してください。")

    suspect = [c.strip().upper() for c in args.countries.split(",") if c.strip()]
    control = [c.strip().upper() for c in args.controls.split(",") if c.strip()]
    html_hash = os.environ.get("SV_HTML_HASH")

    out = {"tool": "surge_breakdown", "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
           "split_date": args.split_date, "countries": suspect, "controls": control, "results": {}}
    for name, q, facets in build_groups(suspect, control, args.split_date, html_hash):
        t0 = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        r, note = count(api, q, facets)
        if r is None:
            out["results"][name] = {"query": q, "queried_at": t0, "error": note}
            print(f"{name:20s} ERROR {note}", flush=True)
        else:
            f = r.get("facets", {}) or {}
            conc = {k: top_share(f.get(k, [])) for k in ("org", "asn", "port", "http.html_hash") if f.get(k)}
            out["results"][name] = {"query": q, "queried_at": t0, "total": r["total"],
                                    "top3_share": conc, "facets": f, "note": note}
            print(f"{name:20s} {r['total']:>6}  上位3つの割合={conc}" + (f"  [{note}]" if note else ""), flush=True)
        time.sleep(1.1)

    out["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    with open(fn, "w") as fp:
        json.dump(out, fp, ensure_ascii=False, indent=1)
    print(f"保存しました: {fn}")


if __name__ == "__main__":
    main()
