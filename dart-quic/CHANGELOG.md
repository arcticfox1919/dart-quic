## 0.1.0

Initial release.

- QUIC client and server endpoints with async Dart API
- Bidirectional / unidirectional streams and datagram support
- Server supports self-signed (testing), PEM files, and DER in-memory certificates
- Client supports system roots, custom CA, or skip-verification modes
- Tokio async runtime managed internally — no manual setup needed
