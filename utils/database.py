import sqlite3
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime
import logging

logger = logging.getLogger("MoD.database")

class Database:
    """SQLite database for storing scan results and vulnerabilities."""
    
    def __init__(self):
        """Initialize database with scan and vulnerability tables."""
        db_dir = Path.home() / '.mod'
        db_dir.mkdir(parents=True, exist_ok=True)
        
        self.db_path = db_dir / 'scans.db'
        self.conn = None
        self.init_database()
    
    def __enter__(self):
        """Context manager entry - open database connection."""
        self.conn = sqlite3.connect(self.db_path)
        logger.debug("Database connection opened")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close database connection.
        
        Args:
            exc_type: Exception type if an error occurred.
            exc_val: Exception value if an error occurred.
            exc_tb: Exception traceback if an error occurred.
        """
        if self.conn:
            self.conn.close()
            logger.debug("Database connection closed")
        return False
    
    def init_database(self) -> None:
        """Create database tables if they don't exist.
        
        Raises:
            sqlite3.Error: If database initialization fails.
        """
        try:
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
            logger.debug("Database initialized successfully")
        
        except sqlite3.Error as e:
            logger.exception(f"Database initialization error: {e}")
            raise
    
    def save_scan(self, target_url: str, vulnerabilities: List[Dict]) -> Optional[int]:
        """Save scan results to database.
        
        Args:
            target_url: Target URL that was scanned.
            vulnerabilities: List of vulnerability dictionaries.
            
        Returns:
            Scan ID in database.
            
        Raises:
            sqlite3.Error: If save operation fails.
        """
        try:
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
            logger.info(f"Scan {scan_id} saved with {len(vulnerabilities)} vulnerabilities")
            return scan_id
        
        except sqlite3.Error as e:
            logger.exception(f"Error saving scan: {e}")
            raise
    
    def get_scan(self, scan_id: int) -> Dict:
        """Retrieve scan results by ID.
        
        Args:
            scan_id: Scan ID in database.
            
        Returns:
            Dictionary with scan info and vulnerabilities.
        """
        try:
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
        
        except sqlite3.Error as e:
            logger.exception(f"Error retrieving scan {scan_id}: {e}")
            return {'scan': None, 'vulnerabilities': []}
    
    def get_all_scans(self, limit: int = 100) -> List[Dict]:
        """Retrieve all scans with pagination.
        
        Args:
            limit: Maximum number of scans to return.
            
        Returns:
            List of scan records.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM scans ORDER BY scan_date DESC LIMIT ?', (limit,))
            scans = cursor.fetchall()
            
            conn.close()
            
            return scans
        
        except sqlite3.Error as e:
            logger.exception(f"Error retrieving scans: {e}")
            return []