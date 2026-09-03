#!/usr/bin/env python3
"""us-market：美股技术面快照（Yahoo Finance OHLCV，无 key）。

用法：python3 market.py <TICKER> [range=1y] [interval=1d]
输出：JSON {symbol, price, ma20/ma50/ma200 + vs 位置, 30d/60d/全年 区间+位置%,
            近14日收盘/涨跌, 52周高低, ytd, 一年涨跌}

网安要点：纯只读，只连 Yahoo 金融端点，与 us-quote 同一 host 白名单。
"""
import json
import sys
import time
import urllib.error
import urllib.request

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
_ENDPOINT = "https://query1.finance.yahoo.com/v8/finance/chart/{t}?range={r}&interval={i}"


def _fetch(ticker: str, range_: str, interval: str) -> tuple[list[float], dict]:
    req = urllib.request.Request(
        _ENDPOINT.format(t=ticker, r=range_, i=interval), headers={"User-Agent": UA}
    )
    last: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read())
            res = data["chart"]["result"][0]
            closes = [c for c in res["indicators"]["quote"][0]["close"] if c is not None]
            return closes, res.get("meta", {})
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            last = exc
        except json.JSONDecodeError as exc:
            last = exc
        except (KeyError, IndexError, TypeError) as exc:  # empty/unknown body
            last = exc
        time.sleep(0.6 * (attempt + 1))
    raise RuntimeError(f"Yahoo chart fetch failed after 3 attempts: {last!r}") from last


def _ma(closes: list[float], n: int) -> float | None:
    return sum(closes[-n:]) / n if len(closes) >= n else None


def _pos_pct(price: float, seg: list[float]) -> float | None:
    lo, hi = min(seg), max(seg)
    if hi == lo:
        return None
    return (price - lo) / (hi - lo) * 100


def analyze(ticker: str, range_: str = "1y", interval: str = "1d") -> dict:
    closes, meta = _fetch(ticker, range_, interval)
    if not closes:
        raise RuntimeError(f"no price data for {ticker}")
    price = closes[-1]
    ma20, ma50, ma200 = _ma(closes, 20), _ma(closes, 50), _ma(closes, 200)

    out = {
        "symbol": meta.get("symbol", ticker.upper()),
        "name": meta.get("longName") or ticker.upper(),
        "price": round(price, 3),
        "series": f"{range_}/{interval}",
        "vs_ma": {
            "ma20": None if ma20 is None else round(ma20, 2),
            "ma50": None if ma50 is None else round(ma50, 2),
            "ma200": None if ma200 is None else round(ma200, 2),
            "pct_vs_ma20": None if ma20 is None else round((price / ma20 - 1) * 100, 2),
            "pct_vs_ma50": None if ma50 is None else round((price / ma50 - 1) * 100, 2),
            "pct_vs_ma200": None if ma200 is None else round((price / ma200 - 1) * 100, 2),
        },
        "ranges": {
            "30d": {"high": round(max(closes[-30:]), 2), "low": round(min(closes[-30:]), 2),
                    "price_pos_pct": round(_pos_pct(price, closes[-30:]), 0) if _pos_pct(price, closes[-30:]) is not None else None},
            "60d": {"high": round(max(closes[-60:]), 2), "low": round(min(closes[-60:]), 2),
                    "price_pos_pct": round(_pos_pct(price, closes[-60:]), 0) if _pos_pct(price, closes[-60:]) is not None else None},
            "ytd": {"high": round(max(closes), 2), "low": round(min(closes), 2),
                    "price_pos_pct": round(_pos_pct(price, closes), 0) if _pos_pct(price, closes) is not None else None},
        },
        "momentum_14d": [round((closes[i] / closes[i - 1] - 1) * 100, 2) for i in range(len(closes) - 13, len(closes))],
        "pct_52w": round((price / meta.get("fiftyTwoWeekLow", price) - 1) * 100, 1) if meta.get("fiftyTwoWeekLow") else None,
        "52week": {"high": meta.get("fiftyTwoWeekHigh"), "low": meta.get("fiftyTwoWeekLow")},
        "previous_close": meta.get("previousClose") or meta.get("chartPreviousClose"),
        "source": "yahoo-finance",
    }
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: market.py <TICKER> [range=1y] [interval=1d]", file=sys.stderr)
        return 2
    r = sys.argv[2] if len(sys.argv) > 2 else "1y"
    interval = sys.argv[3] if len(sys.argv) > 3 else "1d"
    try:
        print(json.dumps(analyze(sys.argv[1], r, interval), ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001 —— CLI 边界统一兜底
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())