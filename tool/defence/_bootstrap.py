# -*- coding: utf-8 -*-
"""冻结环境(打包为 exe) 与源码环境的路径适配

打包后有两个关键差异：
  1. 代码位于 PYZ 归档中，`os.listdir(包目录)` 无法发现子模块
  2. `__file__` 指向临时解压目录(_MEIPASS)，而用户数据(tmp/、备份包、日志)
     应该落在 exe 旁边，否则程序退出即丢失

本模块统一这两处差异，其余代码只需调用这里的函数。
"""
import os
import sys
from pathlib import Path


def is_frozen():
    """是否运行在 PyInstaller 打包出的可执行文件中"""
    return bool(getattr(sys, "frozen", False))


def get_app_dir():
    """程序所在目录。

    - 源码运行: 项目根目录(defence 包的上一级)
    - 打包运行: exe 所在目录
    """
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_resource_dir():
    """只读资源目录(打包内含的 phpwaf 模板等)。

    - 源码运行: 项目根目录
    - 打包运行: PyInstaller 的临时解压目录 _MEIPASS
    """
    if is_frozen():
        base = getattr(sys, "_MEIPASS", None)
        if base:
            return Path(base)
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def get_runtime_dir(sub=None):
    """可写运行目录(日志、下载的源码包、报告)，打包后位于 exe 旁边。"""
    base = get_app_dir() / "tmp"
    if sub:
        base = base / sub
    return base


def get_phpwaf_dir():
    """phpwaf 模板所在目录(只读资源)"""
    return get_resource_dir() / "defence" / "phpwaf"
