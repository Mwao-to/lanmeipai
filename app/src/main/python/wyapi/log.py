# -*- coding: utf-8 -*-
"""log.py — 轻量日志(写文件 + 可选控制台)"""
from __future__ import annotations

import os
import threading
import time

_LOG_DIR = None
_level = 'info'
_lock = threading.Lock()
_console = True

LEVELS = {'debug': 10, 'info': 20, 'warn': 30, 'error': 40}


def init(log_dir: str | None, console: bool = True):
    global _LOG_DIR, _console
    _LOG_DIR = log_dir
    _console = console
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)


class _Logger:
    def __init__(self, name: str):
        self.name = name

    def _write(self, lv: str, msg: str):
        if LEVELS.get(lv, 20) < LEVELS.get(_level, 20):
            return
        line = f'[{time.strftime("%H:%M:%S")}][{lv.upper()}][{self.name}] {msg}'
        if _console:
            try:
                print(line, flush=True)
            except Exception:
                pass
        if _LOG_DIR:
            try:
                with _lock:
                    with open(os.path.join(_LOG_DIR, 'app.log'), 'a', encoding='utf-8') as f:
                        f.write(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] {line}\n')
            except Exception:
                pass

    def debug(self, msg): self._write('debug', str(msg))
    def info(self, msg): self._write('info', str(msg))
    def warn(self, msg): self._write('warn', str(msg))
    def error(self, msg): self._write('error', str(msg))


_loggers: dict = {}


def get_logger(name: str) -> _Logger:
    if name not in _loggers:
        _loggers[name] = _Logger(name)
    return _loggers[name]
