# SSH Stability Iteration

## Implemented

- Added a supervised connection manager in `extra/background.go` with explicit states:
  `idle`, `authenticating`, `connecting`, `connected`, `degraded`, `reconnecting`, `stopped`.
- Kept local SOCKS and HTTP listeners resident while remote websocket tunnels are replaced underneath them.
- Separated SOCKS and HTTP traffic onto distinct websocket tunnels when HTTP proxying is enabled.
- Extended the SMU VPN plugin to maintain login session state, reuse fresh cookies across reconnect attempts, and run a lightweight keepalive while connected.
- Replaced ad hoc websocket writes in core `wssocks` with a single queued writer path and ping/pong health checks with RTT logging.
- Exposed connection state to the Fyne client and Go API wrapper used by the SwiftUI client.

## Intentionally Out Of Scope

- Transparent TCP stream resume across a real tunnel break is still not implemented.
- Existing SSH sessions may still drop if the underlying websocket tunnel is lost.
- This iteration reduces disconnect frequency and recovery time; it does not preserve a broken SSH session.
