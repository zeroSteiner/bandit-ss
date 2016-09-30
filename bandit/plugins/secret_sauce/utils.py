import ast
import collections

import bandit
from . import eval_ast

def get_attribute_name(node, import_aliases=None):
    import_aliases = import_aliases or {}
    if not isinstance(node, ast.Attribute):
        raise ValueError('node must be an instance of ast.Attribute')
    base = node.attr
    name = ''
    node = node.value
    while isinstance(node, ast.Attribute):
        name = node.attr + '.' + name
        node = node.value
    if isinstance(node, ast.Call):
        return None
    if not isinstance(node, ast.Name):
        raise ValueError('could not resolve node for attribute')
    name = (node.id + '.' + name)[:-1]
    return import_aliases.get(name, name) + '.' + base


def get_definition_nodes(parent, name, child=None, prune=True):
    """
    Search nodes between parent and child for the definition of name.

    :param parent: The parent node.
    :type parent: ast.Node
    :param str name: The name of the variable to get definitions for.
    :parem child: The child node.
    :type child: ast.Node
    :param bool prune: Prune definition nodes prior to the last node known to be executed.
    """
    if isinstance(name, ast.Attribute):
        name = get_attribute_name(name)
    if isinstance(name, ast.Name):
        name = name.id
    assign_nodes = collections.deque()
    if name is None:
        return assign_nodes
    path = get_node_path(parent, child)

    def _check_and_add_node(node, top_level=False):
        if node_is_child_of_parent_expr(node, child):
            raise ValueError('node is child of parent, contimination occurred')
        if top_level and prune:
            assign_nodes.clear()
        assign_nodes.append(node)

    for idx, node in enumerate(path[:-1]):
        if node_is_child_of_parent_expr(node, child):
            break
        check_nodes = []
        if isinstance(node, (ast.Break, ast.Continue, ast.Del, ast.Delete, ast.Pass)):
            continue
        next_node = path[idx + 1]
        if isinstance(node, ast.Assign):
            # fixme, process here so it's known to be toplevel
            check_nodes.append(node)
        elif isinstance(node, ast.ClassDef):
            if node.name == name:
                _check_and_add_node(node, top_level=True)
        elif isinstance(node, ast.ExceptHandler):
            if node.name.id == name:
                _check_and_add_node(node, top_level=True)
            check_nodes.extend(node.body)
        elif isinstance(node, ast.For):
            if isinstance(node.target, ast.Name) and node.target.id == name:
                _check_and_add_node(node, top_level=True)
            if next_node in node.body:
                check_nodes.extend(node.body)
            elif next_node in node.orelse:
                check_nodes.extend(node.orelse)
        elif isinstance(node, ast.FunctionDef):
            if node.name == name or name in [arg.id for arg in node.args.args]:
                _check_and_add_node(node, top_level=True)
            check_nodes.extend(node.body)
        elif isinstance(node, ast.If):
            if next_node in node.body:
                check_nodes.extend(node.body)
            elif next_node in node.orelse:
                check_nodes.extend(node.orelse)
        elif isinstance(node, ast.Lambda):
            check_nodes.extend(node.body)
        elif isinstance(node, ast.Module):
            check_nodes.extend(node.body)
        elif isinstance(node, ast.While):
            if next_node in node.body:
                check_nodes.extend(node.body)
            elif next_node in node.orelse:
                check_nodes.extend(node.orelse)

        # prune the subnodes to check so we're not including ones past the child
        if next_node in check_nodes:
            # todo: adjust pruning for proper namespace handling
            check_nodes = check_nodes[:check_nodes.index(next_node)]
        for node in check_nodes:
            if isinstance(node, ast.Assign):
                if node_defines_name(node.value, name):
                    _check_and_add_node(node.value, top_level=True)
                if node_targets_name(node, name):
                    _check_and_add_node(node, top_level=True)
                continue
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                if node.name == name:
                    _check_and_add_node(node, top_level=True)
                continue
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if node_defines_name(node, name):
                    _check_and_add_node(node, top_level=True)
                continue
            for child_node in ast.walk(node):
                if node_defines_name(child_node, name):
                    if isinstance(child_node, ast.Assign) and not node_targets_name(child_node, name):
                        continue
                    _check_and_add_node(child_node)
    return assign_nodes


def get_node_path(parent, child):
    path = [child]
    cursor = getattr(child, 'parent', None)
    while cursor is not None and cursor != parent:
        path.append(cursor)
        cursor = getattr(cursor, 'parent', None)
    if cursor is not None:
        path.append(cursor)
    return list(reversed(path))


def get_top_parent_node(node):
    parent = node.parent
    while getattr(parent, 'parent', None) is not None:
        parent = parent.parent
    return parent


def get_expr_value_src_dst(src_node, dst_node, name):
    test_node = None
    if isinstance(name, ast.Name):
        name = name.id
    if isinstance(dst_node, ast.Name) and dst_node.id == name:
        test_node = src_node
    elif isinstance(dst_node, (ast.List, ast.Tuple)) and isinstance(src_node, (ast.List, ast.Tuple)):
        targets = [elt.id for elt in dst_node.elts if isinstance(elt, ast.Name)]
        if name in targets:
            test_node = src_node.elts[targets.index(name)]
    return test_node


def iter_expr_values(parent, node, child=None):
    """
    Yield each value for *node* which can be tracked. Literals are returned as
    their evaluated value where as nodes which fail to evaluate to literals are
    returned as is.

    :param node parent: The parent node used to mark the start of the search path.
    :param node node: The target ast.Name node to find literal values for.
    :param node child: An optional child node to mark the end of the search path.
    """
    child = child or node
    success, value = eval_ast.literal_expr(node)
    if success:
        yield value
        return
    if not isinstance(node, ast.Name):
        return

    test_nodes = collections.deque()
    def_nodes = get_definition_nodes(parent, node.id, child)
    for def_node_idx, def_node in enumerate(def_nodes):
        each = False
        next_node = (def_nodes[def_node_idx + 1] if len(def_nodes) > def_node_idx + 1 else child)
        src_node = None
        test_nodes.clear()
        if isinstance(def_node, ast.Assign):
            test_node = get_expr_value_src_dst(def_node.value, def_node.targets[0], node)
            if test_node:
                test_nodes.append(test_node)
        elif isinstance(def_node, ast.For):
            src_node = get_expr_value_src_dst(def_node.iter, def_node.target, node)
            each = node_is_child_of_parent(def_node.body, next_node)
        elif isinstance(def_node, ast.ListComp):
            for generator in def_node.generators:
                src_node = get_expr_value_src_dst(generator.iter, generator.target, node)
                if src_node:
                    break

        if isinstance(src_node, (ast.List, ast.Tuple, ast.Set)):
            test_nodes.extend(src_node.elts if each else src_node.elts[-1:])

        for test_node in test_nodes:
            success, value = eval_ast.literal_expr(test_node)
            if success:
                yield value
                continue
            for value in iter_expr_values(parent, test_node):
                success = True
                yield value
            if success:
                continue
            for def_node in get_definition_nodes(parent, test_node):
                for value in iter_expr_values(parent, def_node):
                    success = True
                    yield value
            yield test_node


def iter_expr_literal_values(parent, node, child=None):
    """
    Yield each value for *node* which can be tracked to a literal expression.

    :param node parent: The parent node used to mark the start of the search path.
    :param node node: The target ast.Name node to find literal values for.
    :param node child: An optional child node to mark the end of the search path.
    """
    for value in iter_expr_values(parent, node, child):
        if isinstance(value, ast.AST):
            continue
        yield value


def iter_imported_modules(node):
    """
    Yield the imported module names from *node* where *node* is either an
    ast.Import or ast.ImportFrom instance.
    """
    if isinstance(node, ast.Import):
        for alias in node.names:
            yield alias.name
    elif isinstance(node, ast.ImportFrom):
        for alias in node.names:
            yield node.module + '.' + alias.name
    else:
        raise ValueError('node must be an instance of either ast.Import or ast.ImportFrom')


def iter_method_classes(parent, call_node, child=None, import_aliases=None):
    import_aliases = import_aliases or {}
    if not isinstance(call_node, ast.Call):
        raise ValueError('call_node must be of type ast.Call')
    if not isinstance(call_node.func, ast.Attribute):
        raise ValueError('call_node must be an attribute')
    for init_node in iter_expr_values(parent, call_node.func.value, call_node):
        # the init_node is the one in which the class is initialized
        # all expr nodes should be either call (Name or Attribute) or Name
        if not isinstance(init_node, ast.Call):
            continue
        if isinstance(init_node.func, ast.Attribute):
            module_name, klass_name = get_attribute_name(init_node.func).rsplit('.', 1)
            for def_node in get_definition_nodes(parent, init_node.func.value, child=init_node):
                if isinstance(def_node, (ast.Import, ast.ImportFrom)):
                    yield import_aliases.get(module_name, module_name) + '.' + klass_name
        elif isinstance(init_node.func, ast.Name):
            for klass_node in iter_expr_values(parent, init_node.func):
                if isinstance(klass_node, ast.Attribute):
                    yield get_attribute_name(klass_node, import_aliases)


def get_call_arg_values(parent, call_node, arg=None, kwarg=None, child=None):
    """Only returns literals."""
    if not isinstance(call_node, ast.Call):
        raise ValueError('call_node must be an ast.Call instance')
    if arg is None and kwarg is None:
        raise RuntimeError('either an arg or kwarg must be specified')
    arg_node = None
    if arg is not None:
        if not isinstance(arg, int):
            raise ValueError('arg must be specified as a 0-indexed argument position')
        if arg < len(call_node.args):
            arg_node = call_node.args[arg]
    if arg_node is None and kwarg is not None:
        if not isinstance(kwarg, str):
            raise ValueError('kwarg must be specified as the string of a keyword argument name')
        arg_node = next((kw.value for kw in call_node.keywords if kw.arg == kwarg), None)
    if arg_node is None:
        return
    if not hasattr(arg_node, 'parent'):
        arg_node.parent = call_node
    for arg_value in iter_expr_literal_values(parent, arg_node, child=child):
        yield arg_value


def get_call_attr_chain(call_node):
    """
    Get the chain associated with calls to various attributes. The chain is
    returned in the order in which the nodes will be executed.
    """
    calls = collections.deque()
    calls.appendleft(call_node)
    if not isinstance(call_node, ast.Call):
        raise ValueError('call_node must be an ast.Call instance')
    while isinstance(call_node.func, ast.Attribute) and isinstance(call_node.func.value, ast.Call):
        call_node = call_node.func.value
        calls.appendleft(call_node)
    return calls


def get_method_class(parent, call_node, child=None):
    return next(iter_method_classes(parent, call_node, child=child), None)


def iter_child_expr_nodes(node):
    for cursor_node in ast.iter_child_nodes(node):
        yield cursor_node
        for subcursor_node in iter_child_expr_nodes(cursor_node):
            yield subcursor_node


def node_defines_name(node, name):
    """
    Check if the specified statement node defines symbol *name*.

    :param node: The node to check.
    :param name: The symbol name to check.
    :return: Whether or not the node defines the symbole specified.
    :rtype: bool
    """
    if isinstance(name, ast.Name):
        name = name.id

    if isinstance(node, ast.Assign):
        if node_targets_name(node, name):
            return True
        if isinstance(node.value, (ast.DictComp, ast.ListComp, ast.SetComp)):
            return node_defines_name(node.value, name)
    elif isinstance(node, ast.ClassDef):
        return node.name == name
    # these ones all assume the iterable will be executed at least once
    elif isinstance(node, (ast.DictComp, ast.GeneratorExp, ast.ListComp, ast.SetComp)):
        for generator in node.generators:
            target = generator.target
            if isinstance(target, ast.Name):
                if target.id == name:
                    return True
                continue
            for child_node in iter_child_expr_nodes(target):
                if isinstance(child_node, ast.Name) and child_node.id == name:
                    return True
        return False
    elif isinstance(node, ast.ExceptHandler):
        if isinstance(node.name, ast.Name):
            return node.name.id == name
    elif isinstance(node, ast.Expr):
        if isinstance(node.value, (ast.DictComp, ast.GeneratorExp, ast.ListComp, ast.SetComp)):
            return node_defines_name(node.value, name)
    elif isinstance(node, ast.For):
        return isinstance(node.target, ast.Name) and node.target.id == name
    elif isinstance(node, ast.FunctionDef):
        return node.name == name
    elif isinstance(node, (ast.Import, ast.ImportFrom)):
        return next((alias for alias in node.names if (alias.asname or alias.name) == name), None) is not None
    return False


def node_is_child_of_parent(parent, child):
    if not isinstance(parent, ast.AST):
        for child_node in parent:
            if node_is_child_of_parent(child_node, child):
                return True
    else:
        for child_node in ast.walk(parent):
            if child_node == child:
                return True
    return False


def node_is_child_of_parent_expr(parent, child):
    for cursor_node in ast.iter_child_nodes(parent):
        if cursor_node == child or (isinstance(cursor_node, ast.expr) and node_is_child_of_parent_expr(cursor_node, child)):
            return True
    return False


def node_targets_name(node, name):
    if not isinstance(node, ast.Assign):
        raise TypeError('node must be an instance of ast.Assign')
    for target in node.targets:
        if isinstance(target, ast.Name):
            if target.id == name:
                return True
        else:
            for child_node in iter_child_expr_nodes(target):
                if isinstance(child_node, ast.Name) and child_node.id == name:
                    return True
    return False


def report_hardcoded_credentials(lib_name, username=None, password=None):
    if username is not None and password is not None:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            text="Hard-coded credentials are being passed to the {0} library for authentication.".format(lib_name)
        )
    if username is not None:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text="A hard-coded username is being passed to the {0} library for authentication.".format(lib_name)
        )
    if password is not None:
        return bandit.Issue(
            severity=bandit.MEDIUM,
            confidence=bandit.MEDIUM,
            text="A hard-coded password is being passed to the {0} library for authentication.".format(lib_name)
        )


def report_method_auth_literal(libname, context, username, password, classes):
    call_node = context.node
    parent = get_top_parent_node(call_node)
    klass_name = next(
        (klass for klass in iter_method_classes(parent, call_node, import_aliases=context._context['import_aliases']) if klass in classes),
        None
    )
    if klass_name is None:
        return
    username_node = next(get_call_arg_values(parent, call_node, arg=username[0], kwarg=username[1]), None)
    password_node = next(get_call_arg_values(parent, call_node, arg=password[0], kwarg=password[1]), None)
    return report_hardcoded_credentials(libname, username_node, password_node)
