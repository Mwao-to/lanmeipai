# -*- coding: utf-8 -*-
"""加密字节码加载器 —— 本文件不含任何业务逻辑,明文随包无妨。

业务代码 main_app 以 AES-256-CBC 加密的 Python 3.8 字节码形式存放于
assets/core.bin(构建期由 CI 生成),Java 层用拆分混淆的密钥解密后,
经 install() 直接在内存中装载执行 —— 全程不产生明文源码/字节码文件。
"""
import marshal
import sys
import types


def install(code_bytes):
    """装载 main_app 模块字节码并注册到 sys.modules。

    code_bytes: 已去掉 pyc 头(16 字节)的 marshal 字节码(由 Java 解密得到)。
    """
    code = marshal.loads(code_bytes)
    mod = sys.modules.get('main_app')
    if mod is None:
        mod = types.ModuleType('main_app')
        mod.__name__ = 'main_app'
        sys.modules['main_app'] = mod
    mod.__file__ = '<core>'
    mod.__package__ = None
    exec(code, vars(mod))
    return True
