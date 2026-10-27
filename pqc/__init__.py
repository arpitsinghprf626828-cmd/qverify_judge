"""Quantum-safe trust layer (Member 2 owns this package).
registry    - trusted key registry (root-signed), revoke/reinstate
signing     - ML-DSA (+Ed25519 hybrid) signed verification reports, QR, benchmark
credentials - issuer-signed credentials embedded in documents (offline verification)
vault       - ML-KEM-768 + AES-256-GCM sealed storage of uploaded files
audit       - hash-chained audit log with ML-DSA-signed Merkle checkpoints
"""
