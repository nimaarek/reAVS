import json
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional


class ScanDatabase:
    def __init__(self, db_path: str = "reavs_history.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                apk_path TEXT NOT NULL,
                apk_name TEXT,
                scan_mode TEXT,
                depth INTEGER,
                timestamp TEXT,
                status TEXT,
                total_vulns INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                results_json TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                vuln_index INTEGER,
                vuln_type TEXT,
                vuln_location TEXT,
                ignored INTEGER DEFAULT 0,
                comment TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS custom_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT UNIQUE,
                rule_type TEXT,
                pattern TEXT,
                severity TEXT,
                description TEXT,
                enabled INTEGER DEFAULT 1,
                timestamp TEXT
            )
        """)

        conn.commit()
        conn.close()

    def save_scan(
        self, apk_path: str, scan_mode: str, depth: int, results: Dict[str, Any]
    ) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        apk_name = apk_path.split("/")[-1].split("\\")[-1]
        timestamp = datetime.now().isoformat()

        vulns = results.get("vulnerabilities", [])
        critical = sum(1 for v in vulns if v.get("severity", "").upper() == "CRITICAL")
        high = sum(1 for v in vulns if v.get("severity", "").upper() == "HIGH")
        medium = sum(1 for v in vulns if v.get("severity", "").upper() == "MEDIUM")
        low = sum(1 for v in vulns if v.get("severity", "").upper() == "LOW")

        cursor.execute(
            """
            INSERT INTO scans
            (apk_path, apk_name, scan_mode, depth, timestamp, status,
             total_vulns, critical_count, high_count, medium_count, low_count, results_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                apk_path,
                apk_name,
                scan_mode,
                depth,
                timestamp,
                results.get("status", "unknown"),
                len(vulns),
                critical,
                high,
                medium,
                low,
                json.dumps(results, ensure_ascii=False),
            ),
        )

        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return scan_id

    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, apk_name, scan_mode, depth, timestamp, status,
                   total_vulns, critical_count, high_count, medium_count, low_count
            FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
        """,
            (limit,),
        )

        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "id": row[0],
                "apk_name": row[1],
                "scan_mode": row[2],
                "depth": row[3],
                "timestamp": row[4],
                "status": row[5],
                "total_vulns": row[6],
                "critical": row[7],
                "high": row[8],
                "medium": row[9],
                "low": row[10],
            }
            for row in rows
        ]

    def get_scan_by_id(self, scan_id: int) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return {
            "id": row[0],
            "apk_path": row[1],
            "apk_name": row[2],
            "scan_mode": row[3],
            "depth": row[4],
            "timestamp": row[5],
            "status": row[6],
            "total_vulns": row[7],
            "critical": row[8],
            "high": row[9],
            "medium": row[10],
            "low": row[11],
            "results": json.loads(row[12]) if row[12] else {},
        }

    def mark_false_positive(
        self,
        scan_id: int,
        vuln_index: int,
        vuln_type: str,
        vuln_location: str,
        ignored: bool = True,
        comment: str = "",
    ):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO false_positives
            (scan_id, vuln_index, vuln_type, vuln_location, ignored, comment, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                scan_id,
                vuln_index,
                vuln_type,
                vuln_location,
                1 if ignored else 0,
                comment,
                datetime.now().isoformat(),
            ),
        )

        conn.commit()
        conn.close()

    def get_false_positives(self, scan_id: int) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT vuln_index, vuln_type, vuln_location, ignored, comment
            FROM false_positives
            WHERE scan_id = ?
        """,
            (scan_id,),
        )

        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "index": row[0],
                "type": row[1],
                "location": row[2],
                "ignored": bool(row[3]),
                "comment": row[4],
            }
            for row in rows
        ]

    def compare_versions(self, scan_id1: int, scan_id2: int) -> Dict[str, Any]:
        scan1 = self.get_scan_by_id(scan_id1)
        scan2 = self.get_scan_by_id(scan_id2)

        if not scan1 or not scan2:
            return {"error": "One or both scans not found"}

        vulns1 = {
            v.get("type", "") + v.get("location", ""): v
            for v in scan1["results"].get("vulnerabilities", [])
        }
        vulns2 = {
            v.get("type", "") + v.get("location", ""): v
            for v in scan2["results"].get("vulnerabilities", [])
        }

        new_vulns = [v for k, v in vulns2.items() if k not in vulns1]
        fixed_vulns = [v for k, v in vulns1.items() if k not in vulns2]
        common_vulns = [v for k, v in vulns2.items() if k in vulns1]

        return {
            "scan1": scan1,
            "scan2": scan2,
            "new_vulnerabilities": new_vulns,
            "fixed_vulnerabilities": fixed_vulns,
            "common_vulnerabilities": common_vulns,
            "stats": {
                "new": len(new_vulns),
                "fixed": len(fixed_vulns),
                "common": len(common_vulns),
            },
        }

    def save_custom_rule(
        self,
        rule_name: str,
        rule_type: str,
        pattern: str,
        severity: str,
        description: str,
    ) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO custom_rules
                (rule_name, rule_type, pattern, severity, description, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    rule_name,
                    rule_type,
                    pattern,
                    severity,
                    description,
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def get_custom_rules(self) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, rule_name, rule_type, pattern, severity, description, enabled
            FROM custom_rules
            ORDER BY timestamp DESC
        """)

        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "id": row[0],
                "name": row[1],
                "type": row[2],
                "pattern": row[3],
                "severity": row[4],
                "description": row[5],
                "enabled": bool(row[6]),
            }
            for row in rows
        ]

    def delete_custom_rule(self, rule_id: int) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
        conn.commit()
        deleted = cursor.rowcount > 0
        conn.close()

        return deleted
