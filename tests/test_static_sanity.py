"""静态体检：无需运行服务即可拦住"一跑就崩"的低级错误。

背景：`maintain_valid_nodes()` 里曾出现 `state.get(...)`，而 `state` 从来不是
模块级全局变量——每次刷新节点都会抛 NameError，但因为该分支没有任何单元测试
覆盖，这个致命 bug 一直没被发现。本文件用标准库 ast/symtable 做全量静态检查，
成本极低、覆盖全部源码，专门防这一类"引用了不存在的名字"。
"""

import ast
import builtins
import symtable
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SOURCES = sorted(p for p in _ROOT.glob("*.py"))
_BUILTINS = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__package__", "__compiled__"}


def _module_level_names(table: symtable.SymbolTable) -> set[str]:
    return {s.get_name() for s in table.get_symbols() if s.is_assigned() or s.is_imported()}


def _undefined_globals(path: Path) -> list[str]:
    """返回 [函数路径:名字]，表示函数里读了一个模块里根本不存在的全局名。"""
    src = path.read_text(encoding="utf-8")
    top = symtable.symtable(src, str(path), "exec")
    known = _module_level_names(top) | _BUILTINS
    problems: list[str] = []

    def walk(table: symtable.SymbolTable, prefix: str) -> None:
        for child in table.get_children():
            where = f"{prefix}/{child.get_name()}"
            if child.get_type() == "function":
                for sym in child.get_symbols():
                    name = sym.get_name()
                    if sym.is_global() and not sym.is_assigned() and name not in known:
                        problems.append(f"{where}:{name}")
            walk(child, where)

    walk(top, path.name)
    return problems


class TestNoUndefinedGlobals(unittest.TestCase):
    def test_every_module_has_no_undefined_global(self):
        self.assertTrue(_SOURCES, "未找到任何源码文件，测试路径可能不对")
        found: list[str] = []
        for path in _SOURCES:
            found.extend(_undefined_globals(path))
        self.assertEqual(
            found,
            [],
            "以下位置引用了不存在的全局变量，运行时必定抛 NameError：\n  " + "\n  ".join(found),
        )


class TestNoBareExcept(unittest.TestCase):
    """裸 `except:` 会连 KeyboardInterrupt / SystemExit 一起吞掉，导致服务无法正常退出。"""

    def test_no_bare_except(self):
        offenders: list[str] = []
        for path in _SOURCES:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    offenders.append(f"{path.name}:{node.lineno}")
        self.assertEqual(offenders, [], "存在裸 except：\n  " + "\n  ".join(offenders))


class TestNoShellInjectionSurface(unittest.TestCase):
    """禁止 shell=True / os.system / eval / exec——本项目所有外部命令都必须用参数列表。"""

    FORBIDDEN_CALLS = {"eval", "exec", "compile"}

    def test_no_shell_true(self):
        offenders: list[str] = []
        for path in _SOURCES:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        offenders.append(f"{path.name}:{node.lineno} shell=True")
                func = node.func
                dotted = ""
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    dotted = f"{func.value.id}.{func.attr}"
                elif isinstance(func, ast.Name):
                    dotted = func.id
                if dotted in ("os.system", "os.popen"):
                    offenders.append(f"{path.name}:{node.lineno} {dotted}")
                if dotted in self.FORBIDDEN_CALLS:
                    offenders.append(f"{path.name}:{node.lineno} {dotted}()")
        self.assertEqual(offenders, [], "存在命令注入/动态执行风险：\n  " + "\n  ".join(offenders))


class TestAllSourcesCompile(unittest.TestCase):
    def test_compile(self):
        for path in _SOURCES:
            with self.subTest(module=path.name):
                compile(path.read_text(encoding="utf-8"), str(path), "exec")


if __name__ == "__main__":
    unittest.main()
