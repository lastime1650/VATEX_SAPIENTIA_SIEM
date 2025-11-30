import sqlite3

import threading

class SqliteManager:
    def __init__(self, DB_PATH: str = None):
        if DB_PATH is None:
            raise ValueError("DB_PATH를 지정해야 합니다.")
        self.DB_PATH = DB_PATH
        self.thread_lock = threading.Lock()

    def _connect(self):
        """DB 연결 및 커서 반환"""
        conn = sqlite3.connect(self.DB_PATH)
        conn.row_factory = sqlite3.Row  # 결과를 dict-like 형태로 반환
        return conn

    def Query(self, query: str) -> list[dict]:
        """SELECT 전용: 결과를 리스트(dict)로 반환"""
        try:
            conn = self._connect()
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            result = [dict(row) for row in rows]
            return result
        except sqlite3.Error as e:
            print(f"Query Error: {e}")
            return []
        finally:
            conn.close()

    def Execute(self, execute: str) -> bool:
        
        with self.thread_lock:
            """INSERT, UPDATE, CREATE 등 실행"""
            try:
                conn = self._connect()
                cursor = conn.cursor()
                cursor.execute(execute)
                conn.commit()
                return True
            except sqlite3.Error as e:
                print(f"Execute Error: {e}")
                return False
            finally:
                conn.close()


'''
이제 event_id 를 자동 매핑하는 로직을 구현해야한다. (여기말고따로만들어야함 Auto-Mapping_Event_Id.py)
'''