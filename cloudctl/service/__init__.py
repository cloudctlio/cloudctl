"""The control plane as a service: an HTTP API (FastAPI) over the policy gate,
the orchestrator and the drift loop, with shared state (DynamoDB, Cosmos DB or
Firestore) and the gate's immutable audit sink. Run with ``cloudctl serve``."""
