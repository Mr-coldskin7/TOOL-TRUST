#!/usr/bin/env python3
"""us-quote：查询美股实时行情（Yahoo Finance chart API，无 key）。

用法：python3 quote.py <TICKER>
输出：JSON {symbol, name, currency, price, change, change_pct, previous_close, ts}

网安要点（供 attestation 对账）：
  - 纯只读：不写任何文件、不传参外数据
  - 只连 Yahoo 金融端点 query1/query2.finance.yahoo.com:443
  - 带有限超时，失败走 stderr 并以非零退出
"""
import json
import sys
import time
import urllib.error
import urllib.request

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
_ENDPOINTS = (
    "https://query1.finance.yahoo.com/v8/finance/chart/{t}?range=1d&interval=1m",
    "https://query2.finance.yahoo.com/v8/finance/chart/{t}?range=1d&interval=1m",
)


def fetch(ticker: str) -> dict:
    last_err = None
    for url in _ENDPOINTS:
        try:
            req = urllib.request.Request(url.format(t=ticker), headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            meta = data["chart"]["result"][0]["meta"]
            return _summarize(ticker, meta)
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, json.JSONDecodeError) as e:
            last_err = e
    raise RuntimeError(f"all quote endpoints failed: {last_err!r}")


def _summarize(ticker: str, meta: dict) -> dict:
    price = meta.get("regularMarketPrice")
    prev = meta.get("chartPreviousClose") or meta.get("previousClose")
    change = (price - prev) if (price is not None and prev is not None) else None
    pct = (change / prev * 100) if (change is not None and prev) else None
    return {
        "symbol": meta.get("symbol", ticker.upper()),
        "name": meta.get("longName") or meta.get("shortName") or ticker.upper(),
        "currency": meta.get("currency"),
        "price": price,
        "change": None if change is None else round(change, 3),
        "change_pct": None if pct is None else round(pct, 3),
        "previous_close": prev,
        "ts": int(time.time()),
        "source": "yahoo-finance",
    }


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: quote.py <TICKER>", file=sys.stderr)
        return 2
    try:
        print(json.dumps(fetch(sys.argv[1]), ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001 —— CLI 边界统一兜底
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())