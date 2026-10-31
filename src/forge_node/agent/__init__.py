"""forge-node agent (Design 3.1, 4.5): unprivileged, outbound mTLS to the hub only, T0 reads and result relay. No sudo, no listener, no write path to anything privileged.
Slice N2 delivers the T0 path; the privileged relay to privd and the audit file writer arrive with N3 (gate D)."""
