# Auto-deploy

Redeploys the stack on the host whenever `main` advances on GitHub. A systemd
timer polls the remote HEAD every two minutes; when the deployed revision is
behind, it fast-forwards the checkout and runs `docker compose up -d --build`.
If the remote and deployed revisions match it is a no-op, so the poll is cheap.

No secret lives in GitHub. The only credential is a token that can read the
(private) repo, kept in a root-only file on the host.

## Install (on the host)

```sh
# 1. token that can read the repo (contents:read is enough)
printf '%s' 'ghp_xxx' > /root/.noblechat-deploy-token
chmod 600 /root/.noblechat-deploy-token

# 2. the poller
install -m 755 deploy/autodeploy/noblechat-autodeploy.sh /root/noblechat-autodeploy.sh
install -m 644 deploy/autodeploy/noblechat-autodeploy.service /etc/systemd/system/
install -m 644 deploy/autodeploy/noblechat-autodeploy.timer   /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now noblechat-autodeploy.timer
```

Logs: `/root/noblechat-autodeploy.log`. Trigger once by hand with
`systemctl start noblechat-autodeploy.service`.
