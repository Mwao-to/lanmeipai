# -*- coding: utf-8 -*-
"""wyapp-core:业务核心 AOT 编译包

main_app.py(含全部业务逻辑与内嵌界面)经 Cython 编译为 C 扩展,
由 Chaquopy 构建期自动用 NDK 交叉编译为 arm64 原生机器码(.so)。
APK 内不存在任何业务 .py/.pyc 字节码,字节码反编译器(uncompyle6/pycdc 等)完全失效,
静态逆向难度等同原生 App。

注意:sdist 内已包含预生成的 src/main_app.c,
Chaquopy 目标环境中无需安装 Cython,直接编译 C。
本地重新生成流程:修改 src/main_app.py 后运行 ./rebuild.sh 重打包。
"""
import os
from setuptools import setup, Extension

SRC = "src/main_app.c"
if os.path.exists(SRC):
    # 预生成 C 已就绪(发布路径):目标环境零 Cython 依赖
    ext_modules = [Extension("main_app", [SRC])]
else:
    # 开发路径:现场用 Cython 转译
    from Cython.Build import cythonize
    ext_modules = cythonize(
        [Extension("main_app", ["src/main_app.py"])],
        language_level=3,
        # 不启用 boundscheck/wraparound/cdivision 优化指令:
        # 代码含负索引(pkcs7_unpad 等),保持 100% Python 语义优先
    )

setup(
    name="wyapp-core",
    version="1.0",
    description="NetEase player/downloader core (AOT compiled, no bytecode shipped)",
    packages=[],
    ext_modules=ext_modules,
)
