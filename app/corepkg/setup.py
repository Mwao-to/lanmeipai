# -*- coding: utf-8 -*-
"""wyapp-core:业务核心 AOT 编译包

main_app.py(含全部业务逻辑与内嵌界面)经 Cython 编译为 C 扩展,
由 Chaquopy 构建期自动用 NDK 交叉编译为 arm64 原生机器码(.so)。
APK 内不存在任何业务 .py/.pyc 字节码,字节码反编译器(uncompyle6/pycdc 等)完全失效,
静态逆向难度等同原生 App。
"""
from setuptools import setup, Extension
from Cython.Build import cythonize

setup(
    name="wyapp-core",
    version="1.0",
    description="NetEase player/downloader core (AOT compiled, no bytecode shipped)",
    packages=[],
    ext_modules=cythonize(
        [Extension("main_app", ["src/main_app.py"])],
        language_level=3,
        compiler_directives={
            "boundscheck": False,       # 逻辑为纯 Python 语义,关闭越界检查提速
            "wraparound": False,
            "cdivision": True,
        },
    ),
)
