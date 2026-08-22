# 业务核心保护流水线

src/main_app.py 是唯一业务源码(单一数据源)。

构建期(CI,见 .github/workflows/build.yml):
1. 真实 Python 3.8 将 main_app.py 编译为字节码(pyc),去掉 16 字节头取 marshal 体
2. AES-256-CBC 加密为 app/src/main/assets/core.bin
   密钥与 MainActivity 中拆片异或存储的分片一一对应

运行期:
1. Java 层拼装分片还原密钥 → 解密 core.bin(纯内存)
2. pyloader.install(bytes) 在内存中 marshal.loads + exec 装载 main_app 模块
3. 全程无明文源码/字节码落盘,APK 内不可直接提取任何业务代码

修改 main_app.py 后无需任何本地操作 —— 推送后 CI 自动重新编译加密。
