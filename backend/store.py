import json
import sqlite3
import threading
import time
from pathlib import Path


class Store:
    def __init__(self, path, recover=True):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS memory (id INTEGER PRIMARY KEY,kind TEXT NOT NULL,content TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY,conversation TEXT NOT NULL,role TEXT NOT NULL,content TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY,tool TEXT NOT NULL,args TEXT NOT NULL,state TEXT NOT NULL,result TEXT,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY,level TEXT NOT NULL,message TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS schedules (id INTEGER PRIMARY KEY,tool TEXT NOT NULL,args TEXT NOT NULL,due REAL NOT NULL,state TEXT NOT NULL);
        ''')
        if recover:
            self.recover()

    def recover(self):
        self.execute("UPDATE tasks SET state='interrupted',result='Server restarted before completion' WHERE state IN ('queued','running')")
        self.execute("UPDATE schedules SET state='interrupted' WHERE state='running'")

    def execute(self, sql, args=()):
        with self.lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur.lastrowid

    def rows(self, sql, args=()):
        with self.lock:
            return [dict(row) for row in self.db.execute(sql, args).fetchall()]

    def get(self, key, default=None):
        rows = self.rows('SELECT value FROM settings WHERE key=?', (key,))
        return json.loads(rows[0]['value']) if rows else default

    def set(self, key, value):
        self.execute('INSERT OR REPLACE INTO settings VALUES (?,?)', (key, json.dumps(value)))

    def event(self, message, level='info'):
        self.execute('INSERT INTO events(level,message,created) VALUES (?,?,?)', (level, message, time.time()))
