import ast
from bandit.plugins.secret_sauce import utils as s_utils

class TaintablePath(object):
    def __init__(self, target_node, tainted_node, context=None):
        self.target_node = target_node
        self.tainted_node = tainted_node
        if not s_utils.node_is_child_of_parent(target_node, tainted_node):
            raise ValueError('tainted_node must be a child of target_node')
        self.context = context

    def __bool__(self):
        return self._solve()

    def __nonzero__(self):
        return self._solve()

    def _solve(self):
        import_aliases = (self.context._context['import_aliases'] if self.context else None)
        cursor_node = self.tainted_node.parent
        while cursor_node != self.target_node:
            test_node = cursor_node
            cursor_node = cursor_node.parent
            if isinstance(test_node, ast.BinOp):
                continue
            elif isinstance(test_node, ast.Call):
                if isinstance(test_node.func, ast.Attribute) and isinstance(test_node.func.value, ast.Str) and test_node.func.attr == 'format':
                    return True
                function = s_utils.get_call_function(test_node, import_aliases=import_aliases)
                if function in ('os.path.abspath', 'os.path.join', 'str'):
                    continue
                elif function == 'os.path.relpath' and s_utils.node_is_child_of_parent(test_node.args[0], self.tainted_node):
                    continue
            elif isinstance(test_node, ast.Subscript):
                continue
            return False
        return True


def set_parents(node):
    for child in ast.iter_child_nodes(node):
        setattr(child, 'parent', node)
        set_parents(child)

def main():
    mod = ast.parse("""open(os.path.join(foo, tainted + '/')[:3], 'rb')""")
    set_parents(mod)
    sink = mod.body[0].value
    taint = next((n for n in ast.walk(mod) if isinstance(n, ast.Name) and n.id == 'tainted'))
    taintable = TaintablePath(
        sink,
        taint
    )
    if taintable:
        print('it is taintable')
    else:
        print('it is not taintable')

if __name__ == '__main__':
    main()
