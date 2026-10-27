#!/usr/bin/env python3
"""Race Shop: a deliberately vulnerable, localhost-only coupon race lab.

Run on Kali:       python3 race_shop.py
Check the demo:    python3 race_shop.py --self-test
Choose a port:     python3 race_shop.py --port 5001

Python 3.9+; standard library only. Open http://127.0.0.1:5000 inside Kali.
Use Burp Suite's browser. Capture POST /cart/coupon with coupon=SAVE10,
reset the coupon, then send 10 identical requests in parallel in Repeater.
The server uses HTTP/1.1; Burp can use last-byte synchronization.

The 500 ms delay intentionally widens a real check-then-act race for teaching.
State lives in memory in ONE process. Fixed mode holds a per-cart lock across
validation and redemption. This is a classroom fix for this single process;
distributed production services need an atomic database operation/transaction
or an equivalent shared concurrency control covering the entire operation.
No actual payments, accounts, third-party requests, or persistent data.
"""

import argparse
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from html import escape
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import secrets
import threading
import time
from urllib.parse import parse_qs, urlsplit


PRODUCTS = [
    ("headphones", "Studio headphones", "Audio", 20000, "headphones", "#e8eafc"),
    ("keyboard", "Wireless keyboard", "Workspace", 8000, "keyboard", "#e6f1ed"),
    ("mouse", "Precision mouse", "Workspace", 4000, "mouse", "#faeddf"),
    ("hub", "USB-C hub", "Accessories", 6000, "hub", "#e5eef7"),
    ("charger", "Compact charger", "Power", 3000, "charger", "#f6e6ec"),
    ("ssd", "Portable SSD", "Storage", 15000, "ssd", "#ede9f4"),
    ("camera", "HD webcam", "Video", 10000, "camera", "#eaf1df"),
]
BY_ID = {p[0]: p for p in PRODUCTS}
ICONS = {
    "headphones": '<path d="M14 37v-8a18 18 0 0 1 36 0v8"/><rect x="10" y="32" width="10" height="20" rx="5"/><rect x="44" y="32" width="10" height="20" rx="5"/>',
    "keyboard": '<rect x="5" y="18" width="54" height="30" rx="5"/><path d="M13 26h2m7 0h2m7 0h2m7 0h2m7 0h2M13 34h2m7 0h2m7 0h2m7 0h2m7 0h2M20 41h24"/>',
    "mouse": '<rect x="18" y="8" width="28" height="48" rx="14"/><path d="M32 8v18M18 28h28"/><rect x="30" y="15" width="4" height="10" rx="2"/>',
    "hub": '<rect x="7" y="26" width="50" height="23" rx="5"/><path d="M22 26V14h20V8M15 35v5m9-5v5m9-5v5m9-5v5"/>',
    "charger": '<rect x="17" y="23" width="30" height="32" rx="6"/><path d="M25 23V10m14 13V10M34 31l-7 10h9l-6 8"/>',
    "ssd": '<rect x="13" y="9" width="38" height="47" rx="6"/><path d="M23 20h18M24 46h16"/><circle cx="41" cy="36" r="2"/>',
    "camera": '<rect x="8" y="14" width="48" height="30" rx="7"/><circle cx="32" cy="29" r="9"/><path d="M25 44v8h14v-8M20 55h24"/>',
}


def money(cents):
    return f"${cents / 100:,.2f}"


@dataclass
class Cart:
    items: dict = field(default_factory=dict)
    applied: int = 0
    mode: str = "vulnerable"
    epoch: int = 0
    serial: int = 0
    events: deque = field(default_factory=lambda: deque(maxlen=80))
    lock: object = field(default_factory=threading.RLock)
    clock: float = field(default_factory=time.monotonic)
    receipt: object = None

    def subtotal(self):
        return sum(BY_ID[key][3] * quantity for key, quantity in self.items.items())

    def snapshot(self):
        with self.lock:
            subtotal = self.subtotal()
            discount = min(subtotal, self.applied * 1000)
            return {"items": dict(self.items), "applications": self.applied,
                    "subtotal_cents": subtotal, "discount_cents": discount,
                    "total_cents": subtotal - discount, "mode": self.mode,
                    "events": list(self.events), "receipt": self.receipt}

    def reset_coupon(self):
        # Invalidates requests already sleeping in an older demo round.
        self.epoch += 1
        self.applied = 0
        self.serial = 0
        self.events.clear()
        self.clock = time.monotonic()
        self.receipt = None

    def event(self, request_id, phase, message):
        self.events.append({"ms": round((time.monotonic() - self.clock) * 1000),
                            "request": request_id, "phase": phase, "message": message})


def redeem(cart, code, delay):
    """Return (HTTP status, message). The intentional race is only in this function."""
    with cart.lock:
        epoch = cart.epoch
        cart.serial += 1
        request_id = cart.serial
        if code != "SAVE10":
            cart.event(request_id, "REJECTED", "Unknown coupon. Use SAVE10.")
            return 400, "Unknown coupon. Enter SAVE10."
        if not cart.items:
            cart.event(request_id, "REJECTED", "Cart is empty.")
            return 400, "Add a product first."
        if cart.applied > 0:
            cart.event(request_id, "REJECTED", "Coupon already used.")
            return 409, "Coupon already used. Only one redemption is allowed."
        cart.event(request_id, "CHECK", "Coupon is unused; validation passed.")

        if cart.mode == "fixed":
            # FIX: keep the SAME lock held across check, delay, and redemption.
            time.sleep(delay)
            cart.applied += 1
            cart.event(request_id, "APPLIED", "$10 coupon applied; code marked used.")
            return 200, "SAVE10 applied once: $10 off."

    # BUG: the lock has been released, but the code has not been marked used.
    # Other requests can pass the same validation while this request sleeps.
    # This intentional pause makes the timing window easy to demonstrate.
    time.sleep(delay)

    with cart.lock:
        if cart.epoch != epoch:
            return 409, "The demo was reset or the cart changed. Retry this round."
        # Deliberately no second coupon-used check here. Each accepted request
        # contributes its own redemption, so discounts can accumulate.
        cart.applied += 1
        cart.event(request_id, "APPLIED", f"$10 coupon applied; redemption #{cart.applied}.")
        return 200, f"SAVE10 applied. Redemptions this round: {cart.applied}."


CSS = """
:root{font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:#182a31;background:#f6f7f7;font-size:15px}
*{box-sizing:border-box}body{margin:0}a{color:#12665b}button,input{font:inherit}button,a,input,summary{ -webkit-tap-highlight-color:transparent }
button:focus-visible,a:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #2a8e7e;outline-offset:3px}
header{background:#fff;border-bottom:1px solid #e2e7e5}nav{max-width:1280px;margin:auto;padding:22px 30px;display:flex;align-items:center;justify-content:space-between;gap:18px}
.brand{font-size:24px;font-weight:800;letter-spacing:-1px;display:flex;align-items:center;gap:10px}.brandmark{background:#173e37;color:#fff;padding:5px 9px;border-radius:9px;font-size:21px}.brand small{font-size:11px;color:#6c7775;letter-spacing:1.3px;font-weight:600;margin-left:18px;text-transform:uppercase}
.tag{font-size:12px;background:#f2f5f4;border:1px solid #d9e4df;padding:7px 12px;border-radius:100px;white-space:nowrap}.tag.warn{color:#8a4a12;background:#fff2df;border-color:#f0d6b6}.tag.good{color:#16634f;background:#e6f5ec;border-color:#baddc6}
main{max-width:1280px;margin:auto;padding:30px}.intro{display:flex;justify-content:space-between;align-items:end;gap:20px;margin-bottom:24px}.eyebrow{font-size:11px;letter-spacing:1.8px;text-transform:uppercase;color:#58736b;font-weight:750}h1{font-size:36px;line-height:1.15;letter-spacing:-1.4px;margin:10px 0}p{line-height:1.6;color:#61716f;margin:0}.intro p{max-width:620px}.textlink{font-size:13px;white-space:nowrap}
.layout{display:grid;grid-template-columns:minmax(0,1fr) 354px;gap:26px;align-items:start}.catalog-title{display:flex;justify-content:space-between;align-items:center;margin:0 0 14px}h2{font-size:18px;letter-spacing:-.35px;margin:0}.muted{color:#76847f;font-size:12px}.products{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:15px}
.product{background:#fff;border:1px solid #e1e7e3;border-radius:15px;padding:13px;display:flex;flex-direction:column}.product-art{height:105px;display:flex;justify-content:center;align-items:center;border-radius:10px;color:#334a4e}.product-art svg{width:70px;height:70px;stroke:currentColor;fill:none;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}.category{font-size:10px;text-transform:uppercase;letter-spacing:1.4px;color:#77877e;margin-top:15px}.product h3{font-size:14px;line-height:1.4;margin:5px 0 13px;font-weight:650;min-height:20px}.product-bottom{display:flex;align-items:center;justify-content:space-between;margin-top:auto;gap:6px}.price{font-size:15px;font-weight:700}.add{background:#eef4f0;color:#22584a;border:1px solid #dce8e0;border-radius:8px;padding:6px 10px;font-size:12px;cursor:pointer}.add:hover{background:#dcece2}
.cart{background:#fff;border:1px solid #dce5df;border-radius:16px;overflow:hidden;position:sticky;top:20px}.cart-header{padding:21px 21px 17px;border-bottom:1px solid #e8ece9;display:flex;justify-content:space-between;align-items:center}.cart-body{padding:20px}.empty{border:1px dashed #d3dfd7;background:#f8faf8;padding:24px 15px;border-radius:10px;text-align:center;margin-bottom:18px;font-size:13px}.empty b{display:block;margin-bottom:6px;color:#304e41}.cart-row{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:0 0 18px;font-size:12px}.cart-name{font-weight:650;margin-bottom:5px}.quantity{display:flex;align-items:center;gap:7px;color:#68766c}.quantity form{display:inline}.quantity button{background:#f1f4f1;border:1px solid #dbe4dd;border-radius:5px;width:23px;height:23px;padding:0;cursor:pointer}.coupon-box{background:#f3f7f4;border:1px solid #e3ebe4;border-radius:11px;padding:14px;margin:10px 0 20px}.coupon-box label{display:block;font-weight:650;font-size:13px;margin-bottom:5px}.coupon-box p{font-size:11px;margin-bottom:11px}.inputline{display:flex;gap:7px}.inputline input{min-width:0;width:100%;border:1px solid #cddad0;background:#fff;border-radius:7px;padding:9px 10px;color:#153e2a;letter-spacing:1px;font-size:13px}.primary{background:#1e5745;color:#fff;border:0;border-radius:7px;padding:10px 13px;font-size:12px;font-weight:600;cursor:pointer}.primary:hover{background:#153e31}.totals>div{display:flex;justify-content:space-between;font-size:13px;margin-bottom:10px}.totals .discount{color:#297052}.totals .grand{border-top:1px solid #e0e6e1;padding-top:15px;margin:15px 0;font-weight:750;font-size:22px;letter-spacing:-.4px}.count{display:flex;justify-content:space-between;border-radius:7px;background:#f6f4ef;padding:9px 10px;font-size:11px;margin-bottom:16px;color:#655435}.count.bad{color:#8f421b;background:#fff0e2}.checkout{width:100%;padding:12px;font-size:13px}button:disabled{opacity:.45;cursor:not-allowed}.cart-note{font-size:10px;text-align:center;margin-top:10px}
.controls{margin-top:24px;background:#fff;border:1px solid #e0e7e2;border-radius:13px;padding:18px 20px;display:flex;align-items:center;justify-content:space-between;gap:12px}.controls-title{font-weight:700;font-size:13px}.controls p{font-size:11px;margin-top:3px}.controls-actions{display:flex;gap:8px;align-items:center}.secondary{background:#fff;border:1px solid #cddbd2;padding:9px 12px;border-radius:7px;cursor:pointer;font-size:12px;color:#2e4f40;white-space:nowrap}.secondary:hover{background:#f0f5f1}.flash{padding:13px 16px;border-radius:9px;margin:0 0 20px;background:#e8f2ec;border:1px solid #c4dccd;color:#244e38;font-size:13px}.flash.error{background:#fff1e4;border-color:#f0d3b1;color:#8c4c1a}.flash:empty{display:none}.receipt{padding:15px;background:#edf7ed;border-radius:10px;margin-bottom:20px;font-size:13px;line-height:1.6}
.learn{margin-top:20px;background:#fff;border:1px solid #e0e7e2;border-radius:13px;padding:0 20px}.learn summary{padding:17px 0;cursor:pointer;font-weight:650;font-size:13px}.learn-content{padding:0 0 20px;max-width:850px;font-size:13px;line-height:1.8;color:#53665c}.learn li{margin-bottom:7px}.learn ol{padding-left:20px;margin:0 0 12px}.learn code,.trace code{font-family:ui-monospace,monospace;font-size:12px;background:#edf2ef;border-radius:4px;padding:2px 4px}.learn p{margin-bottom:10px}.trace{margin-top:20px;background:#fff;border:1px solid #e0e7e2;border-radius:13px;padding:20px}.trace-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px}.trace h2{font-size:14px}.table-wrap{overflow:auto;max-height:255px}table{border-collapse:collapse;width:100%;font-size:12px;text-align:left}th{background:#f4f7f5;color:#6b7970;font-size:10px;letter-spacing:1px;padding:10px;text-transform:uppercase;position:sticky;top:0}td{padding:9px 10px;border-bottom:1px solid #eef1ee;white-space:nowrap}td:last-child{white-space:normal;min-width:220px}.phase{font-size:10px;font-weight:750}.phase.APPLIED{color:#227443}.phase.REJECTED{color:#a26027}.phase.CHECK{color:#4f63a0}footer{padding:27px 0 2px;font-size:11px;color:#7b887f;line-height:1.7}.demo-hint{font-size:11px;margin-top:14px}
@media(max-width:1100px){.layout{grid-template-columns:minmax(0,1fr) 325px}.products{grid-template-columns:repeat(2,minmax(0,1fr))}.brand small{display:none}}
@media(max-width:760px){nav{padding:18px 20px}main{padding:24px 20px}.layout{grid-template-columns:1fr}.cart{position:static}.intro{display:block}h1{font-size:31px}.intro .textlink{display:inline-block;margin-top:12px}.controls{align-items:start;flex-direction:column}.controls-actions{flex-wrap:wrap}.trace{padding:15px}.brand{font-size:22px}.tag{font-size:10px;padding:6px 8px}}
@media(prefers-reduced-motion:no-preference){button{transition:background .15s}}
"""

SCRIPT = """
const flash = document.querySelector('#flash');
try { const notice = JSON.parse(sessionStorage.getItem('race-shop-notice') || 'null');
  sessionStorage.removeItem('race-shop-notice');
  if (notice) { flash.textContent = notice.message; flash.classList.toggle('error', !notice.ok); }
} catch (_) {}
document.addEventListener('submit', async event => {
  const form = event.target;
  event.preventDefault();
  const data = new URLSearchParams(new FormData(form));
  const button = form.querySelector('button');
  if (button) button.disabled = true;
  try {
    const response = await fetch(form.action, {method:'POST', body:data, credentials:'same-origin'});
    const result = await response.json();
    sessionStorage.setItem('race-shop-notice', JSON.stringify({message:result.message, ok:response.ok}));
    window.location.replace('/');
  } catch (_) {
    flash.textContent = 'Could not reach the shop. Check that the Python terminal is still running and Burp Intercept is off.';
    flash.classList.add('error');
    if (button) button.disabled = false;
  }
});
"""


def render(cart, delay):
    s = cart.snapshot()
    fixed = s["mode"] == "fixed"
    cards = []
    for key, name, category, price, icon, color in PRODUCTS:
        cards.append(f'''<article class="product"><div class="product-art" style="background:{color}">
        <svg viewBox="0 0 64 64" aria-hidden="true">{ICONS[icon]}</svg></div>
        <div class="category">{category}</div><h3>{name}</h3><div class="product-bottom">
        <span class="price">{money(price)}</span><form action="/cart/add" method="post">
        <input type="hidden" name="product" value="{key}"><button class="add" aria-label="Add {name}">+ Add</button></form></div></article>''')
    rows = []
    for key, quantity in s["items"].items():
        product = BY_ID[key]
        rows.append(f'''<div class="cart-row"><div><div class="cart-name">{product[1]}</div>
        <div class="quantity"><form action="/cart/remove" method="post"><input type="hidden" name="product" value="{key}">
        <button aria-label="Remove one {product[1]}">−</button></form><span>Qty {quantity}</span>
        <form action="/cart/add" method="post"><input type="hidden" name="product" value="{key}">
        <button aria-label="Add one {product[1]}">+</button></form></div></div><b>{money(product[3] * quantity)}</b></div>''')
    empty = '<div class="empty"><b>Your cart is ready for a demo.</b>Add the $200 headphones to get started.</div>'
    logs = ''.join(f'<tr><td>{event["ms"]:,} ms</td><td>#{event["request"]}</td><td class="phase {event["phase"]}">{event["phase"]}</td><td>{escape(event["message"])}</td></tr>' for event in s["events"])
    if not logs:
        logs = '<tr><td colspan="4">No coupon requests yet. Apply SAVE10 to see the server steps here.</td></tr>'
    receipt = ''
    if s["receipt"]:
        r = s["receipt"]
        receipt = f'<div class="receipt"><b>Simulated order placed.</b><br>Paid {money(r["total_cents"])} for {money(r["subtotal_cents"])} of products with {r["applications"]} coupon redemption(s). No payment was processed.</div>'
    mode_label = 'Fixed mode' if fixed else 'Vulnerable mode'
    mode_target = 'vulnerable' if fixed else 'fixed'
    mode_button = 'Switch to vulnerable' if fixed else 'Switch to fixed'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Race Shop · Coupon race condition lab</title><style>{CSS}</style></head><body>
    <header><nav><div class="brand"><span class="brandmark" aria-hidden="true">R</span>Race Shop<small>Security teaching lab</small></div>
    <span class="tag {'good' if fixed else 'warn'}">{'●' if fixed else '◉'} {mode_label}</span></nav></header>
    <main><section class="intro"><div><div class="eyebrow">One coupon. One redemption. Or is it?</div><h1>A little timing. A big discount.</h1>
    <p>Add a product, try SAVE10, then explore what happens when requests arrive together.</p></div><a class="textlink" href="#guide">Burp demo guide ↗</a></section>
    <div id="flash" class="flash" role="status" aria-live="polite"></div>{receipt}
    <div class="layout"><section aria-label="Products"><div class="catalog-title"><h2>The everyday collection</h2><span class="muted">7 products</span></div>
    <div class="products">{''.join(cards)}</div><p class="demo-hint">Demo tip: start with the $200 headphones. Ten successful SAVE10 redemptions make the total $100.</p></section>
    <aside class="cart" aria-label="Shopping cart"><div class="cart-header"><h2>Your cart</h2><span class="muted">{sum(s['items'].values())} item(s)</span></div><div class="cart-body">
    {''.join(rows) if rows else empty}<div class="coupon-box"><form action="/cart/coupon" method="post"><label for="coupon">A little something off.</label><p>Use <b>SAVE10</b> for $10 off. One use per cart.</p>
    <div class="inputline"><input id="coupon" name="coupon" value="SAVE10" autocomplete="off" spellcheck="false" maxlength="30"><button class="primary">Apply</button></div></form></div>
    <div class="totals"><div><span>Subtotal</span><span>{money(s['subtotal_cents'])}</span></div><div class="discount"><span>Coupon savings</span><span>−{money(s['discount_cents'])}</span></div>
    <div class="grand"><span>Total</span><span>{money(s['total_cents'])}</span></div></div>
    <div class="count {'bad' if s['applications'] > 1 else ''}"><span>Coupon redemptions</span><b>{s['applications']} / 1 allowed</b></div>
    <form action="/cart/checkout" method="post"><button class="primary checkout" {'disabled' if not s['items'] else ''}>Place demo order</button></form><p class="cart-note">Simulated purchase · no payment information</p></div></aside></div>
    <section class="controls" aria-label="Instructor controls"><div><div class="controls-title">Instructor controls</div><p>Reset keeps your products. Switching mode starts a fresh coupon round.</p></div><div class="controls-actions">
    <form action="/cart/reset" method="post"><button class="secondary">Reset coupon</button></form><form action="/demo/mode" method="post"><input type="hidden" name="mode" value="{mode_target}"><button class="secondary">{mode_button}</button></form><a href="/" class="secondary" style="text-decoration:none">Refresh results</a></div></section>
    <details class="learn" id="guide"><summary>Classroom walkthrough · Burp Suite Repeater</summary><div class="learn-content"><ol>
    <li>Start Burp Suite in Kali. Use <b>Proxy → Intercept → Open browser</b>, keep <b>Intercept off</b>, and open <b>http://127.0.0.1:5000</b> (or your chosen port).</li>
    <li>Add the $200 headphones. Click <b>Apply</b> for SAVE10. The total becomes $190.</li>
    <li>In <b>Proxy → HTTP history</b>, find <code>POST /cart/coupon</code>. Right-click → <b>Send to Repeater</b>. The body is <code>coupon=SAVE10</code>. Keep the same session cookie.</li>
    <li>Click <b>Reset coupon</b> in the shop. Send that request once in Repeater: <b>200 OK</b>. Send it again after the first finishes: <b>409 Conflict</b>, already used. Refresh the shop: one redemption.</li>
    <li>In Repeater, click the <b>+</b> tab button → <b>Create tab group</b>. Name the group, select your coupon tab, and click <b>Create</b>. Right-click the tab within the group → <b>Duplicate tab</b> nine times, making ten tabs total.</li>
    <li>Click <b>Reset coupon</b> in the shop again and wait for the reset to finish. In Repeater select a grouped tab, open the arrow beside <b>Send</b>, select <b>Send group in parallel</b>, then click <b>Send group</b>.</li>
    <li>After all responses finish, click <b>Refresh results</b> in the shop. Multiple redemptions show the race; ten accepted requests give $100 total. The exact count depends on overlap.</li>
    <li>Click <b>Switch to fixed</b> (this resets the coupon), send the same group in parallel, then refresh. Only one request should succeed; the total is $190.</li></ol>
    <p><b>Why it happens:</b> multiple requests check an unused coupon before any one marks it used. All accepted requests then apply their discount. Sequential reuse fails; overlapping requests can succeed.</p>
    <p><b>Teaching delay:</b> this lab deliberately pauses for {round(delay * 1000)} ms between validation and redemption. This widens a real server-side race; it is not a production timing estimate.</p>
    <p><b>Fixed mode:</b> one per-cart lock covers validation and redemption in this single Python process. A production service with multiple workers or servers needs a shared atomic transaction/conditional update; a process-local lock alone is insufficient.</p>
    <p><b>If parallel sending is unavailable:</b> select a tab inside the group; use a recent Burp Suite (2023.9+); keep all requests on the same host and port. For HTTP/1, disable HTTP/1 connection reuse under Settings → Tools → Repeater. This lab uses HTTP/1.1; Burp synchronizes requests using the last byte. HTTP/2 single-packet mode is not required.</p>
    <p><b>Start over:</b> reset the coupon between attempts and wait for all requests to finish before changing the cart. Adding or removing products resets the coupon. Restarting Python clears every cart. Use the same browser tab and cookie throughout the demo.</p>
    <p>Official reference: <a href="https://portswigger.net/burp/documentation/desktop/tools/repeater/send-group" target="_blank" rel="noreferrer">PortSwigger: sending grouped requests</a>.</p></div></details>
    <section class="trace" aria-label="Request trace"><div class="trace-head"><h2>Inside the server</h2><span class="muted">Latest 80 events · refresh after sending</span></div><div class="table-wrap"><table><thead><tr><th>Time since reset</th><th>Request</th><th>Step</th><th>What happened</th></tr></thead><tbody>{logs}</tbody></table></div></section>
    <footer>Deliberately vulnerable classroom lab. Bound to 127.0.0.1 by default. In-memory carts, seven fictional products, no real transactions.<br>The total stops at $0. The redemption count still shows any extra uses. Stop the server with Ctrl+C.</footer>
    </main><script>{SCRIPT}</script></body></html>'''


class ShopServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128

    def __init__(self, address, delay=0.5, quiet=False):
        self.carts = {}
        self.carts_lock = threading.Lock()
        self.delay = delay
        self.quiet = quiet
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RaceShop/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, fmt, *args):
        if not self.server.quiet:
            super().log_message(fmt, *args)

    def cart(self):
        jar = cookies.SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            pass
        token = jar["race_session"].value if "race_session" in jar else None
        self.new_cookie = None
        with self.server.carts_lock:
            if token not in self.server.carts:
                token = secrets.token_urlsafe(24)
                self.server.carts[token] = Cart()
                self.new_cookie = token
            return self.server.carts[token]

    def respond(self, status, data, content_type="application/json; charset=utf-8"):
        body = (json.dumps(data) if content_type.startswith("application/json") else data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        if getattr(self, "new_cookie", None):
            self.send_header("Set-Cookie", f"race_session={self.new_cookie}; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def do_GET(self):
        cart = self.cart()
        path = urlsplit(self.path).path
        if path == "/":
            self.respond(200, render(cart, self.server.delay), "text/html; charset=utf-8")
        elif path == "/api/cart":
            self.respond(200, cart.snapshot())
        else:
            self.respond(404, {"message": "Page not found."})

    def do_POST(self):
        cart = self.cart()
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc != self.headers.get("Host"):
            return self.respond(403, {"message": "Use the shop's own page or Burp request."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 4096:
                raise ValueError
            params = parse_qs(self.rfile.read(length).decode("utf-8"), max_num_fields=10)
        except (ValueError, UnicodeError):
            return self.respond(400, {"message": "Invalid form body."})
        path = urlsplit(self.path).path
        if path == "/cart/coupon":
            code = params.get("coupon", [""])[0].strip().upper()
            status, message = redeem(cart, code, self.server.delay)
        else:
            status = 200
            with cart.lock:
                if path in ("/cart/add", "/cart/remove"):
                    key = params.get("product", [""])[0]
                    if key not in BY_ID:
                        return self.respond(400, {"message": "Unknown product."})
                    change = 1 if path == "/cart/add" else -1
                    quantity = max(0, min(99, cart.items.get(key, 0) + change))
                    if quantity:
                        cart.items[key] = quantity
                    else:
                        cart.items.pop(key, None)
                    cart.reset_coupon()
                    message = "Cart updated. Coupon round reset."
                elif path == "/cart/reset":
                    cart.reset_coupon()
                    message = "Coupon reset. Your products and session are unchanged."
                elif path == "/demo/mode":
                    mode = params.get("mode", [""])[0]
                    if mode not in ("vulnerable", "fixed"):
                        return self.respond(400, {"message": "Unknown mode."})
                    cart.mode = mode
                    cart.reset_coupon()
                    message = f"Now in {mode} mode. Coupon reset."
                elif path == "/cart/checkout":
                    if not cart.items:
                        return self.respond(400, {"message": "Your cart is empty."})
                    receipt = cart.snapshot()
                    cart.items.clear()
                    cart.reset_coupon()
                    cart.receipt = {key: receipt[key] for key in ("total_cents", "subtotal_cents", "applications")}
                    message = "Demo order placed. No real payment was processed."
                else:
                    status, message = 404, "Endpoint not found."
        self.respond(status, {"message": message, "cart": cart.snapshot()})


def self_test():
    """Exercise real concurrent HTTP requests against an ephemeral loopback port."""
    server = ShopServer(("127.0.0.1", 0), quiet=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    cookie = ""

    def request(method, path, body="", session=None):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie if session is None else session}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        result = (response.status, json.loads(raw), response.getheader("Set-Cookie"))
        connection.close()
        return result

    def burst(count=10):
        barrier = threading.Barrier(count)
        def worker(_):
            barrier.wait(timeout=10)
            return request("POST", "/cart/coupon", "coupon=SAVE10")[0]
        with ThreadPoolExecutor(max_workers=count) as executor:
            return list(executor.map(worker, range(count)))

    try:
        status, state, cookie_header = request("GET", "/api/cart")
        assert status == 200 and not state["items"]
        cookie = cookie_header.split(";", 1)[0]
        assert request("POST", "/cart/coupon", "coupon=SAVE10")[0] == 400
        request("POST", "/cart/add", "product=headphones")
        assert request("POST", "/cart/coupon", "coupon=WRONG")[0] == 400
        assert request("POST", "/cart/coupon", "coupon=SAVE10")[0] == 200
        assert request("POST", "/cart/coupon", "coupon=SAVE10")[0] == 409
        state = request("GET", "/api/cart")[1]
        assert state["applications"] == 1 and state["total_cents"] == 19000
        print("PASS: sequential requests apply the $10 coupon only once ($190).")

        request("POST", "/cart/reset")
        results = burst()
        state = request("GET", "/api/cart")[1]
        assert results.count(200) >= 2, results
        assert state["applications"] == results.count(200)
        assert state["total_cents"] == 20000 - state["applications"] * 1000
        print(f"PASS: 10 parallel requests -> {state['applications']} redemptions ({money(state['total_cents'])}).")

        request("POST", "/demo/mode", "mode=fixed")
        results = burst()
        state = request("GET", "/api/cart")[1]
        assert results.count(200) == 1 and results.count(409) == 9, results
        assert state["applications"] == 1 and state["total_cents"] == 19000
        print("PASS: fixed mode accepts 1 of 10 parallel requests ($190).")

        assert request("GET", "/api/cart", session="")[1]["items"] == {}
        request("POST", "/cart/checkout")
        state = request("GET", "/api/cart")[1]
        assert state["items"] == {} and state["receipt"]["total_cents"] == 19000
        print("PASS: independent carts, invalid coupons, and simulated checkout.")
        print("All checks passed. Start the shop with: python3 race_shop.py")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def main():
    parser = argparse.ArgumentParser(description="Local coupon race lab; no packages required.")
    parser.add_argument("--port", type=int, default=5000, help="Loopback port (default: 5000)")
    parser.add_argument("--delay-ms", type=int, default=500, help="Teaching race window, 0–5000 ms (default: 500)")
    parser.add_argument("--self-test", action="store_true", help="Run sequential/parallel HTTP checks and exit")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not 1 <= args.port <= 65535 or not 0 <= args.delay_ms <= 5000:
        parser.error("Use a port from 1 to 65535 and a delay from 0 to 5000 ms.")
    try:
        server = ShopServer(("127.0.0.1", args.port), delay=args.delay_ms / 1000)
    except OSError as error:
        parser.exit(1, f"Cannot start the shop: {error}\nTry: python3 race_shop.py --port 5001\n")
    print(f"\nRace Shop is ready: http://127.0.0.1:{args.port}\n"
          f"Open this URL INSIDE Kali, preferably in Burp's browser.\n"
          f"Coupon: SAVE10 | {args.delay_ms} ms teaching delay | Localhost only\n"
          "Keep this terminal open. Press Ctrl+C to stop.\n", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShop stopped. In-memory carts discarded.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
