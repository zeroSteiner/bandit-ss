import ast
import operator

AST_BINOP_HANDLERS = {
	ast.Add:      operator.add,
	ast.BitAnd:   operator.and_,
	ast.BitOr:    operator.or_,
	ast.BitXor:   operator.xor,
	ast.Div:      operator.truediv,
	ast.FloorDiv: operator.floordiv,
	ast.LShift:   operator.lshift,
	ast.Mod:      operator.mod,
	ast.Mult:     operator.mul,
	ast.Pow:      operator.pow,
	ast.RShift:   operator.rshift,
	ast.Sub:      operator.sub
}

AST_UNARYOP_HANDLERS = {
	ast.Invert:   operator.invert,
	ast.UAdd:     operator.pos,
	ast.USub:     operator.neg
}

def literal_expr(node, return_name=False):
	if isinstance(node, ast.BinOp):
		success, left_value = literal_expr(node.left)
		if not success:
			return (False, None)
		success, right_value = literal_expr(node.right)
		if not success:
			return (False, None)
		operator_func = AST_BINOP_HANDLERS.get(node.op.__class__)
		if operator_func is not None:
			return (True, operator_func(left_value, right_value))
	elif isinstance(node, ast.Dict):
		value = {}
		for child_key_node, child_value_node in zip(node.keys, node.values):
			success, child_key_value = literal_expr(child_key_node)
			if not success:
				return (False, None)
			success, child_value_value = literal_expr(child_value_node)
			if not success:
				return (False, None)
			value[child_key_value] = child_value_value
		return (True, value)
	elif isinstance(node, ast.List):
		value = list()
		for child_node in node.elts:
			success, child_value = literal_expr(child_node)
			if not success:
				return (False, None)
			value.append(child_value)
		return (True, value)
	elif isinstance(node, ast.Name):
		literal_names = {'False': False, 'None': None, 'True': True}
		if not hasattr(ast, 'NameConstant') and node.id in literal_names:
			return (True, literal_names[node.id])
		if return_name:
			return (None, node)
		return (False, None)
	elif hasattr(ast, 'NameConstant') and isinstance(node, ast.NameConstant):
		return (True, node.value)
	elif isinstance(node, ast.Num):
		return (True, node.n)
	elif isinstance(node, ast.Set):
		value = set()
		for child_node in node.elts:
			success, child_value = literal_expr(child_node)
			if not success:
				return (False, None)
			value.add(child_value)
		return (True, value)
	elif isinstance(node, ast.Str):
		return (True, node.s)
	elif isinstance(node, ast.Tuple):
		value = list()
		for child_node in node.elts:
			success, child_value = literal_expr(child_node)
			if not success:
				return (False, None)
			value.append(child_value)
		return (True, tuple(value))
	elif isinstance(node, ast.UnaryOp):
		success, right_value = literal_expr(node.operand)
		if not success:
			return (False, None)
		operator_func = AST_UNARYOP_HANDLERS.get(node.op.__class__)
		if operator_func is not None:
			return (True, operator_func(right_value))
	return (False, None)
