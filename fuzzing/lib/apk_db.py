import sqlite3
import os
import traceback
from .defs import FUZZ_DB
import logging


class harness:
    def __init__(self, harness, fuzzable, fuzzed, crashes=0):
        self.harness = harness
        self.fuzzable = fuzzable
        self.fuzzed = fuzzed
        self.crashes = crashes


def init_db():
    connection = sqlite3.connect(FUZZ_DB)
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS fuzzdata (
        id INTEGER PRIMARY KEY,
        app TEXT,
        fname TEXT,
        fuzzed TEXT DEFAULT 'no',
        fuzzable TEXT DEFAULT 'unknown',
        crashes INTEGER DEFAULT 0,
        CONSTRAINT unq UNIQUE (app, fname)
    );
    """
    cursor.execute(create_table_query)
    create_fuzzresult_query = """
    CREATE TABLE IF NOT EXISTS fuzzresults (
        id INTEGER PRIMARY KEY,
        fuzzdata_id INTEGER,
        app TEXT,
        fname TEXT,
        fuzzer_instance TEXT DEFAULT 'default',
        start_time INTEGER,
        run_time INTEGER,
        cycles_done INTEGER,
        cycles_wo_finds INTEGER,
        time_wo_finds INTEGER,
        execs_done INTEGER,
        execs_per_sec INTEGER,
        execs_ps_last_min INTEGER,
        corpus_count INTEGER,
        corpus_found INTEGER,
        corpus_imported INTEGER,
        corpus_variable INTEGER,
        pending_favs INTEGER,
        pending_total INTEGER,
        stability TEXT,
        bitmap_cvg TEXT,
        saved_crashes INTEGER,
        saved_hangs INTEGER,
        last_find INTEGER,
        last_crash INTEGER,
        last_hang INTEGER,
        execs_since_crash INTEGER,
        exec_timeout INTEGER,
        slowest_exec_ms INTEGER,
        peak_rss_mb INTEGER,
        cpu_affinity INTEGER,
        edges_found INTEGER,
        total_edges INTEGER,
        FOREIGN KEY(fuzzdata_id) REFERENCES fuzzdata(id)
    );
    """
    cursor.execute(create_fuzzresult_query)
    connection.commit()
    cursor.close()
    connection.close()


def open_db():
    if not os.path.exists(FUZZ_DB):
        init_db()
    connection = sqlite3.connect(FUZZ_DB)
    return connection


def get_fuzz_list(connection, lock=None):
    out = {}
    if lock:
        lock.acquire()
    try:
        cursor = connection.cursor()
        select_data_query = "SELECT * FROM fuzzdata WHERE fuzzed == 'no' AND fuzzable == 'unknown'"
        cursor.execute(select_data_query)
        rows = cursor.fetchall()
        for r in rows:
            Id = r[0]
            app = r[1]
            fname = r[2]
            fuzzed = r[3]
            fuzzable = r[4]
            crashes = r[5]
            if app not in out:
                out[app] = []
            out[app].append(harness(fname, fuzzed, fuzzable, crashes))
        cursor.close()
    except Exception as e:
        logging.error(f'[APKDB] Failed inserting fuzzing results into db {str(e)}, {traceback.format_exc()}')
        print(f'[APKDB] Failed inserting fuzzing results into db {str(e)}, {traceback.format_exc()}')
    finally:
        if lock:
            lock.release()
        return out


def set_fuzzable(connection, app, fname, fuzzable, crashes=0, lock=None):
    if lock:
        lock.acquire()
    try:
        logging.info(f'[APKDB] updating fuzzdata in db {app} {fname} {fuzzable} {crashes}')
        cursor = connection.cursor()
        update_query = "UPDATE fuzzdata SET fuzzable = ?, crashes = ? WHERE app = ? AND fname = ?"
        cursor.execute(update_query, (fuzzable, crashes, app, fname, ))
        connection.commit()
        cursor.close()
    except Exception as e:
        logging.error(f'[APKDB] Failed inserting fuzzing results into db {str(e)}, {traceback.format_exc()}')
        print(f'[APKDB] Failed inserting fuzzing results into db {str(e)}, {traceback.format_exc()}')
    finally:
        if lock:
            lock.release()


def set_fuzzed(connection, app, fname, lock=None):
    if lock:
        lock.acquire()
    try:
        cursor = connection.cursor()
        update_query = "UPDATE fuzzdata SET fuzzed = 'yes' WHERE app = ? AND fname = ?"
        cursor.execute(update_query, (app, fname, ))
        connection.commit()
        cursor.close()
    except Exception as e:
        logging.error(f'[APKDB] Failed inserting fuzzing results into db {str(e)}, {traceback.format_exc()}')
        print(f'[APKDB] Failed inserting fuzzing results into db {str(e)}, {traceback.format_exc()}')
    finally:
        if lock:
            lock.release()


def insert_fuzz_result(connection, app, fname, fetch_out, lock=None):
    if lock:
        lock.acquire()
    try:
        cursor = connection.cursor()
        logging.info(f'[APKDB] updating fuzzresults {app} {fname}')
        select_query = "SELECT id FROM fuzzdata WHERE app = ? AND fname = ?"
        cursor.execute(select_query, (app, fname, ))
        fuzzdata_id = cursor.fetchone()[0]
        for _, data in fetch_out.items():
            insert_query = """
                INSERT INTO fuzzresults (fuzzdata_id, app, fname, fuzzer_instance, start_time, run_time,
                cycles_done, cycles_wo_finds, time_wo_finds, execs_done, execs_per_sec, execs_ps_last_min,
                corpus_count, corpus_found, corpus_imported, corpus_variable, pending_favs, pending_total,
                stability, bitmap_cvg, saved_crashes, saved_hangs, last_find, last_crash, last_hang, 
                execs_since_crash, exec_timeout, slowest_exec_ms, peak_rss_mb, cpu_affinity, edges_found, 
                total_edges) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """
            cursor.execute(insert_query, (fuzzdata_id, app, fname, data['fuzzer_instance'], data['start_time'], data['run_time'],
            data['cycles_done'],data['cycles_wo_finds'],data['time_wo_finds'],data['execs_done'],data['execs_per_sec'],
            data['execs_ps_last_min'],data['corpus_count'],data['corpus_found'],data['corpus_imported'],data['corpus_variable'],
            data['pending_favs'],data['pending_total'],data['stability'],data['bitmap_cvg'],data['saved_crashes'],
            data['saved_hangs'],data['last_find'],data['last_crash'],data['last_hang'],data['execs_since_crash'],
            data['exec_timeout'],data['slowest_exec_ms'],data['peak_rss_mb'],data['cpu_affinity'],data['edges_found'],data['total_edges']))
        connection.commit()
        cursor.close()
    except Exception as e:
        logging.error(f'[APKDB] Failed inserting fuzzing results into db {str(e)}, {traceback.format_exc()}')
        print(f'[APKDB] Failed inserting fuzzing results into db {str(e)}, {traceback.format_exc()}')
    finally:
        if lock:
            lock.release()
