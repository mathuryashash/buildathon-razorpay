"""Reference merchant. Small on purpose.

This exists so the agent has something real to buy from and the eval has a
stable catalogue. It is NOT the product -- do not spend time here. Ten SKUs is
enough to demonstrate an end-to-end purchase; a hundred proves nothing extra.
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException

CATALOG = json.loads((Path(__file__).parent / "catalog.json").read_text())

app = FastAPI(title="Acme Organics (reference merchant)", version="0.1.0")


@app.get("/catalog")
def catalog():
    return CATALOG["products"]


@app.get("/customers")
def customers():
    return CATALOG["customers"]


@app.get("/product/{sku}")
def product(sku: str):
    for p in CATALOG["products"]:
        if p["sku"] == sku:
            return p
    raise HTTPException(404, f"no such sku: {sku}")


@app.post("/quote")
def quote(cart: list[dict]):
    """Price a cart. The merchant is the ONLY source of price truth.

    The agent proposes SKUs and quantities; it never proposes a price. This is
    the same fail-closed instinct as the effect registry: the component that
    could be manipulated does not get to assert the number that matters.
    """
    lines, total = [], 0
    for item in cart:
        p = next((x for x in CATALOG["products"] if x["sku"] == item.get("sku")), None)
        if p is None:
            raise HTTPException(400, f"unknown sku {item.get('sku')!r}")
        qty = int(item.get("qty", 1))
        if qty < 1:
            raise HTTPException(400, "qty must be >= 1")
        if qty > p["stock"]:
            raise HTTPException(409, f"only {p['stock']} of {p['sku']} in stock")
        line = p["price_paise"] * qty
        total += line
        lines.append({"sku": p["sku"], "title": p["title"], "qty": qty,
                      "unit_paise": p["price_paise"], "line_paise": line})
    return {"lines": lines, "total_paise": total}
