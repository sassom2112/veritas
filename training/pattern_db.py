"""
pattern_db.py — SQLite pattern store for GAN training state.

Replaces brain_state.json with versioned, queryable storage.
Compatible with brain.py — ForensicBrain falls back to JSON if DB unavailable.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

_DEFAULT_DB = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'reports', 'patterns.db'
))


class PatternDatabase:
    """
    SQLite-backed store for Blue Agent detection patterns.

    Tables
    ------
    patterns       — one row per (technique, signal) with hit/miss counters
    technique_meta — per-technique weight and name
    training_runs  — one row per accuracy_report() call with metrics
    """

    def __init__(self, db_path=None):
        self.db_path = db_path or _DEFAULT_DB
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_schema()

    # ── Schema ────────────────────────────────────────────────────────────
    def _init_schema(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS technique_meta (
                    technique_id TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    weight       INTEGER DEFAULT 35,
                    updated_at   TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS patterns (
                    technique_id TEXT    NOT NULL,
                    signal       TEXT    NOT NULL,
                    weight       INTEGER DEFAULT 35,
                    hit_count    INTEGER DEFAULT 0,
                    miss_count   INTEGER DEFAULT 0,
                    created_at   TEXT    NOT NULL,
                    last_seen    TEXT,
                    PRIMARY KEY (technique_id, signal)
                );

                CREATE TABLE IF NOT EXISTS training_runs (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp      TEXT    NOT NULL,
                    iteration      INTEGER NOT NULL,
                    detection_rate REAL,
                    f1_score       REAL,
                    metrics_json   TEXT
                );
            """)

    # ── Write ─────────────────────────────────────────────────────────────
    def save_patterns(self, patterns_dict):
        """Upsert all technique weights and signals from BlueAgent.patterns."""
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            for tech_id, data in patterns_dict.items():
                conn.execute("""
                    INSERT INTO technique_meta (technique_id, name, weight, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(technique_id) DO UPDATE SET
                        name       = excluded.name,
                        weight     = excluded.weight,
                        updated_at = excluded.updated_at
                """, (tech_id, data['name'], data['weight'], now))

                for signal in data['signals']:
                    conn.execute("""
                        INSERT INTO patterns
                            (technique_id, signal, weight, hit_count, miss_count, created_at, last_seen)
                        VALUES (?, ?, ?, 0, 0, ?, NULL)
                        ON CONFLICT(technique_id, signal) DO UPDATE SET
                            weight   = excluded.weight,
                            last_seen = ?
                    """, (tech_id, signal, data['weight'], now, now))

    def record_hit(self, technique_id, signal):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE patterns
                SET hit_count = hit_count + 1, last_seen = ?
                WHERE technique_id = ? AND signal = ?
            """, (now, technique_id, signal))

    def record_miss(self, technique_id):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE patterns
                SET miss_count = miss_count + 1
                WHERE technique_id = ?
            """, (technique_id,))

    def record_training_run(self, iteration, detection_rate=0.0,
                            f1_score=0.0, metrics=None):
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO training_runs
                    (timestamp, iteration, detection_rate, f1_score, metrics_json)
                VALUES (?, ?, ?, ?, ?)
            """, (now, iteration, detection_rate, f1_score,
                  json.dumps(metrics or {})))

    # ── Read ──────────────────────────────────────────────────────────────
    def load_patterns(self, base_patterns):
        """
        Return a BlueAgent-compatible patterns dict.
        Merges DB state into base_patterns:
          - DB weights take precedence over base weights
          - DB signals are appended to base signals (no duplicates)
          - Returns base_patterns unchanged if DB has no rows yet
        """
        with sqlite3.connect(self.db_path) as conn:
            meta_rows = conn.execute(
                "SELECT technique_id, weight FROM technique_meta"
            ).fetchall()
            sig_rows = conn.execute(
                "SELECT technique_id, signal FROM patterns"
            ).fetchall()

        if not meta_rows and not sig_rows:
            return base_patterns

        # Build result from base, then overlay DB state
        result = {
            tid: {
                'name': data['name'],
                'signals': list(data['signals']),
                'weight': data['weight'],
            }
            for tid, data in base_patterns.items()
        }

        # Update weights from DB
        for tech_id, weight in meta_rows:
            if tech_id in result:
                result[tech_id]['weight'] = weight

        # Append signals from DB (avoid duplicates)
        for tech_id, signal in sig_rows:
            if tech_id in result and signal not in result[tech_id]['signals']:
                result[tech_id]['signals'].append(signal)

        return result

    def get_low_confidence_signals(self, min_observations=20,
                                   min_hit_rate=0.02):
        """
        Signals where hit_rate < min_hit_rate after ≥ min_observations events.
        Returns [(technique_id, signal, hit_count, miss_count), ...]
        """
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("""
                SELECT technique_id, signal, hit_count, miss_count
                FROM patterns
                WHERE hit_count + miss_count >= ?
                  AND CAST(hit_count AS REAL) / (hit_count + miss_count) < ?
            """, (min_observations, min_hit_rate)).fetchall()

    def get_stats(self):
        with sqlite3.connect(self.db_path) as conn:
            total_signals = conn.execute(
                "SELECT COUNT(*) FROM patterns"
            ).fetchone()[0]
            total_runs = conn.execute(
                "SELECT COUNT(*) FROM training_runs"
            ).fetchone()[0]
            latest = conn.execute("""
                SELECT iteration, detection_rate, f1_score
                FROM training_runs ORDER BY id DESC LIMIT 1
            """).fetchone()
        return {
            'total_signals': total_signals,
            'training_runs': total_runs,
            'latest_run': latest,
        }


if __name__ == '__main__':
    db = PatternDatabase()
    print("DB stats:", db.get_stats())
    print("Low-confidence signals:", db.get_low_confidence_signals())
