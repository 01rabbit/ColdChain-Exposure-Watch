#!/usr/bin/env python3
"""計測結果の JSON から、公開してはいけない情報を取り除く。

exposure_count.py と surge_breakdown.py の出力には、特定の事業者や店舗を推定できる
情報（事業者名・ASN・証明書のホスト名など）が含まれる。結果を公開するときは、
必ずこのスクリプトを通した版を使うこと。

取り除くもの:
- 事業者名（org・isp）、ASN
- 証明書の CN・発行者・フィンガープリント・シリアル
- HTML ハッシュ・ファビコンハッシュ（実機を探す目印になる）
- 製品名以外のページタイトル（店舗名を含むことがある）→ "(other titles, redacted)" にまとめる
- クエリ文字列の中の HTML ハッシュの値 → <REDACTED>

使い方:
    python3 sanitize_for_publication.py counts_20261107_094941.json
    → counts_20261107_094941_public.json を作る
"""
import json
import os
import re
import sys

DROP = {"org", "isp", "asn", "ssl.cert.subject.cn", "ssl.cert.issuer.cn", "ssl.cert.fingerprint",
        "ssl.cert.serial", "http.html_hash", "http.favicon.hash"}
TITLES = {"Danfoss StoreView", "Danfoss - StoreView Web", "StoreView - Login",
          "XWEB", "XWEB EVO", "XWEB PRO"}
HASH = re.compile(r"(http\.html_hash:)-?\d+")


def clean_titles(items):
    keep, other = [], 0
    for x in items:
        if x["value"] in TITLES:
            keep.append(x)
        else:
            other += x["count"]
    if other:
        keep.append({"value": "(other titles, redacted)", "count": other})
    return keep


def sanitize(d):
    for r in d.get("results", {}).values():
        if "query" in r:
            r["query"] = HASH.sub(r"\1<REDACTED>", r["query"])
        f = r.get("facets") or {}
        for k in list(f):
            if k in DROP:
                del f[k]
        if "http.title" in f:
            f["http.title"] = clean_titles(f["http.title"])
    d["public_note"] = ("Sanitized for publication. Removed facets: " + ", ".join(sorted(DROP)) +
                        ". Non-product page titles merged. HTML hash values in queries redacted.")
    return d


def main():
    if len(sys.argv) < 2:
        sys.exit("使い方: python3 sanitize_for_publication.py <計測結果.json> [...]")
    for src in sys.argv[1:]:
        base, ext = os.path.splitext(src)
        dst = f"{base}_public{ext}"
        if os.path.exists(dst):
            print(f"スキップ: {dst} は既に存在します")
            continue
        with open(src) as fp:
            d = json.load(fp)
        with open(dst, "w") as fp:
            json.dump(sanitize(d), fp, ensure_ascii=False, indent=1)
        print(f"作成しました: {dst}")


if __name__ == "__main__":
    main()
