# Access from another trusted computer

The application has no login or multi-user authorization. Keep Compose's `127.0.0.1:8080` publication on the Docker host and use an SSH tunnel rather than exposing HTTP directly:

```sh
# On your client computer; authenticate to a host you control.
ssh -N -L 8080:127.0.0.1:8080 your-user@your-docker-host
```

Open `http://localhost:8080` on the client. SSH authenticates and encrypts the connection; StegoLab's same-host browser protections continue to use localhost. Change the first port if it is already in use, for example `-L 18080:127.0.0.1:8080` then open `http://localhost:18080`.

Do not change the Compose binding to `0.0.0.0` to make an unauthenticated instance public. A reverse proxy deployment would need authenticated access, TLS, request/body/time limits, a firewall, a correctly configured Host allowlist and a review of origin/proxy handling. `STEGOLAB_ALLOWED_HOSTS` alone does not add authentication or tenant isolation. Native-parser jobs still share one worker UID/volume behind any proxy.

Shut down the tunnel when finished. Anyone who can reach the local instance can list investigations, download evidence, queue work and delete data. See [SECURITY.md](../SECURITY.md).
