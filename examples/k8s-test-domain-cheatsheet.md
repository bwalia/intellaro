# Test-domain cheatsheet (k3s1)

The Intellaro data plane is exposed on **NodePort 30880** on every
cluster node; the vhost answers on **`intellaro-test.fictionally.org`**.

Point the domain at a LAN node — either per command:

```bash
R="--resolve intellaro-test.fictionally.org:30880:192.168.1.140"
```

or once, for browsers too (`/etc/hosts`):

```
192.168.1.140  intellaro-test.fictionally.org
```

Apply the use cases:

```bash
kubectl apply -f examples/k8s-demo.yaml           # echo backends (if not present)
kubectl apply -f examples/k8s-test-domain.yaml    # vhost + routes
kubectl -n intellaro-demo get intellaroroutes     # SYNCED should go true
```

## Use cases

The echo backends reply with JSON that names the pod (`echo-a-…` /
`echo-b-…`), so each response shows which route won.

```bash
B=http://intellaro-test.fictionally.org:30880

# 1. Default route → echo-a
curl $R $B/

# 2. Path routing: /api → echo-b
curl $R $B/api/users

# 3. Exact path beats prefix: /api/version → echo-a
curl $R $B/api/version

# 4. Weighted canary: /canary ≈ 80% echo-a / 20% echo-b
for i in $(seq 1 50); do curl -s $R $B/canary | grep -o 'echo-[ab]' | head -1; done | sort | uniq -c

# 5. Header routing: beta testers on /api go to echo-a
curl $R -H 'X-Beta: true' $B/api/users

# 6. Regex path: /r/<digits> → echo-b (non-digits fall to default)
curl $R $B/r/12345
curl $R $B/r/abc

# 7. Method restriction: POST /webhook → echo-b, GET falls through → echo-a
curl $R -X POST -d '{"event":"ping"}' $B/webhook
curl $R $B/webhook

# Forwarding headers as seen by the backend (x-forwarded-for, x-origin-ip)
curl -s $R $B/ | python3 -m json.tool | grep -E 'x-forwarded|x-origin'
```

## Live-change use cases

```bash
# Tighten the rate limit to 5 req/min (expect 429 after 5 requests) …
kubectl -n intellaro-demo patch intellarosecuritypolicy demo-security \
  --type=merge -p '{"spec":{"rateLimit":{"enabled":true,"maxRequests":5,"windowSecs":60}}}'
for i in $(seq 1 8); do curl -s -o /dev/null -w '%{http_code} ' $R $B/; done; echo

# … and back
kubectl -n intellaro-demo patch intellarosecuritypolicy demo-security \
  --type=merge -p '{"spec":{"rateLimit":{"enabled":true,"maxRequests":10000,"windowSecs":60}}}'

# Shift the canary to 50/50 and watch the distribution change
kubectl -n intellaro-demo patch intellaroroute td-canary --type=merge \
  -p '{"spec":{"trafficSplit":[{"backend":{"serviceName":"echo-a","servicePort":80},"weight":50},{"backend":{"serviceName":"echo-b","servicePort":80},"weight":50}]}}'

# Delete a route and watch traffic fall back to the default
kubectl -n intellaro-demo delete intellaroroute td-api
```

## Introspection

```bash
# What the data plane is actually running (rules + upstreams)
kubectl -n intellaro exec deploy/intellaro-dataplane -- \
  curl -s http://localhost:9091/api/v1/config | python3 -m json.tool | less

# Ops endpoints
kubectl -n intellaro exec deploy/intellaro-dataplane -- curl -s http://localhost:9090/health
kubectl -n intellaro exec deploy/intellaro-dataplane -- curl -s http://localhost:9090/metrics | grep proxy_
```

## Phase-1 additions

```bash
# 8. Path rewrite: backend sees the path with /legacy stripped
curl -s $R $B/legacy/users | python3 -c "import sys,json; print(json.load(sys.stdin)['path'])"   # -> /users

# 9. Header manipulation on /api: request gets X-Injected, response gets X-Powered-By
curl -s -D- -o /dev/null $R $B/api/users | grep -i x-powered-by
curl -s $R $B/api/users | python3 -m json.tool | grep -i x-injected
```
