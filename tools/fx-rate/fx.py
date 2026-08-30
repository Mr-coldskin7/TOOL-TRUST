#!/usr/bin/env python3
"""fx-rate：汇率换算（open.er-api.com，无 key，第二数据源）。

用法：python3 fx.py <FROM> <TO> [amount]  例: fx.py USD HKD 100
输出：{from,to,rate,amount,result,updated}
"""
import json
import sys
import urllib.request

UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
_ENDPOINT = "https://open.er-api.com/v6/latest/{base}"


def convert(frm: str, to: str, amount: float) -> dict:
    req = urllib.request.Request(_ENDPOINT.format(base=frm.upper()), headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read())
    rates = data.get("rates", {})
    if data.get("result") != "success" or to.upper() not in rates:
        raise RuntimeError(f"rate not found for {frm}->{to}: {data.get('result')}")
    rate = rates[to.upper()]
    return {
        "from": frm.upper(),
        "to": to.upper(),
        "rate": rate,
        "amount": amount,
        "result": round(amount * rate, 4),
        "updated": data.get("time_last_update_utc"),
        "source": "open.er-api.com",
    }


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: fx.py <FROM> <TO> [amount]", file=sys.stderr)
        return 2
    amount = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0
    try:
        print(json.dumps(convert(sys.argv[1], sys.argv[2], amount), ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
