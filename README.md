# race
Download race_shop.py. It includes:
- Seven products and a shopping cart.
- SAVE10 for a one-time $10 discount.
- A race condition that allows overlapping requests to apply multiple discounts.
- Reset coupon and Fixed mode buttons.
- A Burp walkthrough and request log inside the page.
Save the file inside Kali’s Downloads folder, then run:
cd ~/Downloads
python3 race_shop.py

Keep that terminal open. No extra Python packages are required.

In Burp Suite → Proxy → Intercept → Open browser, turn Intercept off and open http://127.0.0.1:5000. Run both the shop and Burp inside Kali.

To demonstrate:
1. Add the $200 headphones. Apply SAVE10; the total becomes $190.
2. In Proxy → HTTP history, find POST /cart/coupon. Right-click → Send to Repeater.
3. Click Reset coupon in the shop. Send the request once in Repeater, then again after it finishes. The first succeeds; the second says the coupon was already used.
4. Create a Repeater tab group containing that request. Duplicate its tab nine times, giving 10 identical requests. Keep the same session cookie.
5. Click Reset coupon again. In Repeater, use the arrow beside Send → Send group in parallel, then click Send group. This feature works in Community Edition. PortSwigger
6. Refresh the shop. Multiple discounts should appear. Click Switch to fixed, repeat the parallel group, and refresh to show the corrected behavior.
