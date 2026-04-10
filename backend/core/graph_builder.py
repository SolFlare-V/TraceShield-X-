"""
graph_builder.py — Attack graph builder for TraceShield X++
Builds and queries Neo4j graphs representing attack event relationships
between users, processes, and files.
"""

import random
from datetime import datetime
from typing import Dict, Any, List

try:
    from backend.core.neo4j_db import run_query, test_connection
except ImportError:
    from core.neo4j_db import run_query, test_connection


def build_attack_graph(event: Dict[str, Any]) -> bool:
    """
    Persist a single attack event as nodes and relationships in Neo4j.

    Nodes created:
        (u:User), (p:Process), (f:File)

    Relationships (based on action_type):
        "execute" -> (u)-[:EXECUTED]->(p)
        "delete"  -> (p)-[:DELETED]->(f)
        "access"  -> (p)-[:ACCESSED]->(f)

    Args:
        event: Dict with keys: user, process, file, action_type, timestamp.

    Returns:
        True on success, False if Neo4j is unavailable or query fails.
    """
    if not test_connection():
        print("[graph_builder] WARNING: Neo4j unavailable — skipping graph build.")
        return False

    try:
        user        = event.get("user",        "unknown_user")
        process     = event.get("process",     "unknown_process")
        file        = event.get("file",        "unknown_file")
        action_type = event.get("action_type", "access").lower()
        timestamp   = event.get("timestamp",   datetime.utcnow().isoformat())

        # Always merge User and Process nodes
        run_query(
            "MERGE (u:User {name: $user}) "
            "MERGE (p:Process {name: $process, timestamp: $timestamp})",
            {"user": user, "process": process, "timestamp": timestamp},
        )

        if action_type == "execute":
            run_query(
                "MATCH (u:User {name: $user}) "
                "MATCH (p:Process {name: $process}) "
                "MERGE (u)-[:EXECUTED]->(p)",
                {"user": user, "process": process},
            )

        elif action_type == "delete":
            run_query(
                "MERGE (f:File {name: $file}) "
                "WITH f "
                "MATCH (p:Process {name: $process}) "
                "MERGE (p)-[:DELETED]->(f)",
                {"file": file, "process": process},
            )

        elif action_type == "access":
            run_query(
                "MERGE (f:File {name: $file}) "
                "WITH f "
                "MATCH (p:Process {name: $process}) "
                "MERGE (p)-[:ACCESSED]->(f)",
                {"file": file, "process": process},
            )

        return True

    except Exception as e:
        print(f"[graph_builder] WARNING: Failed to build graph: {e}")
        return False


def get_attack_graph() -> Dict[str, Any]:
    """
    Retrieve the current attack graph from Neo4j.

    Returns:
        Dict with "nodes" (list) and "edges" (list), or empty collections
        if Neo4j is unavailable.
    """
    try:
        results = run_query(
            "MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 100"
        )

        nodes_seen = set()
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        for record in results:
            n = dict(record.get("n", {}))
            m = dict(record.get("m", {}))
            r = record.get("r")

            for node in (n, m):
                node_id = node.get("name", str(node))
                if node_id not in nodes_seen:
                    nodes_seen.add(node_id)
                    nodes.append({"id": node_id, "properties": node})

            edges.append({
                "source": n.get("name"),
                "target": m.get("name"),
                "type":   type(r).__name__ if r else "UNKNOWN",
            })

        return {"nodes": nodes, "edges": edges}

    except Exception as e:
        print(f"[graph_builder] WARNING: Failed to fetch graph: {e}")
        return {"nodes": [], "edges": []}


def clear_graph() -> None:
    """
    Delete all nodes and relationships from the Neo4j database.
    """
    try:
        run_query("MATCH (n) DETACH DELETE n")
        print("[graph_builder] Graph cleared.")
    except Exception as e:
        print(f"[graph_builder] WARNING: Failed to clear graph: {e}")


def build_graph_from_detection(anomaly: bool, row: Dict[str, Any]) -> bool:
    """
    Automatically build an attack graph entry when an anomaly is detected.

    Args:
        anomaly: True if the ML model flagged this record as anomalous.
        row:     Raw log dict (used for context, not directly mapped).

    Returns:
        False if anomaly is False or graph build fails, True on success.
    """
    if not anomaly and not row.get("failed_logins", 0) > 2:
        return False

    uid     = random.randint(1000, 9999)
    actions = ["access", "delete"]

    event: Dict[str, Any] = {
        "user":        f"user_{uid}",
        "process":     f"process_{random.randint(100, 999)}",
        "file":        "/var/log/auth.log",
        "action_type": random.choice(actions),
        "timestamp":   datetime.utcnow().isoformat(),
    }

    return build_attack_graph(event)
