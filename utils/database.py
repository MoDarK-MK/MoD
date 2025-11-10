import sqlite3
from pathlib import Path
from typing import List, Dict
from datetime import datetime

class Database:
    def __init__(self):
        db_dir = Path.home() / '.mod'
        db_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = db_dir / 'scans.db'
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                scan_date TEXT NOT NULL,
                total_vulnerabilities INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                url TEXT NOT NULL,
                parameter TEXT,
                payload TEXT,
                description TEXT,
                evidence TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_scan(self, target_url: str, vulnerabilities: List[Dict]) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        scan_date = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO scans (target_url, scan_date, total_vulnerabilities)
            VALUES (?, ?, ?)
        ''', (target_url, scan_date, len(vulnerabilities)))
        
        scan_id = cursor.lastrowid
        
        for vuln in vulnerabilities:
            cursor.execute('''
                INSERT INTO vulnerabilities (
                    scan_id, type, severity, url, parameter, payload, description, evidence
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                vuln.get('type', ''),
                vuln.get('severity', ''),
                vuln.get('url', ''),
                vuln.get('parameter', ''),
                vuln.get('payload', ''),
                vuln.get('description', ''),
                vuln.get('evidence', '')
            ))
        
        conn.commit()
        conn.close()
        
        return scan_id
    
    def get_scan(self, scan_id: int) -> Dict:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
        scan = cursor.fetchone()
        
        cursor.execute('SELECT * FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
        vulnerabilities = cursor.fetchall()
        
        conn.close()
        
        return {
            'scan': scan,
            'vulnerabilities': vulnerabilities
        }
    
    def get_all_scans(self) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM scans ORDER BY scan_date DESC')
        scans = cursor.fetchall()
        
        conn.close()
        
        return scans