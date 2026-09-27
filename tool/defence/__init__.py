"""defence 包：加载全部子模块，对外暴露为 defence.<module>。"""


def _load_all_submodules():
    """导入包内全部子模块。

    两种环境分别处理：
      - 源码运行：扫描目录，新增模块自动生效，顺序固定为字母序
      - 打包(exe)：代码在 PYZ 归档中无法扫描目录，使用固定清单
        （清单需与 defence/ 下的模块保持一致）
    """
    import importlib

    from ._bootstrap import is_frozen

    if is_frozen():
        module_names = [
            "attacker_tools",
            "file_processing",
            "ssh",
            "state",
            "waf_manager",
            "webshell_scanner",
        ]
    else:
        import os

        folder_path = os.path.dirname(__file__)
        module_names = sorted(
            filename[:-3]
            for filename in os.listdir(folder_path)
            if filename.endswith('.py') and filename != '__init__.py'
        )

    for module_name in module_names:
        importlib.import_module(f'.{module_name}', package=__name__)


_load_all_submodules()
