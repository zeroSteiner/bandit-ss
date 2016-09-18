import ast
import re

import bandit
from bandit.core import test_properties as test
from bandit.core import utils as b_utils

from . import utils as s_utils

def _looks_like_sql_string(data):
	val = data.lower().lstrip()
	return ((val.startswith('select ') and ' from ' in val) or
			val.startswith('insert into') or
			(val.startswith('update ') and ' set ' in val) or
			val.startswith('delete from '))

def _check_string_for_sql(ast_str):
	string = ast_str.s
	if not _looks_like_sql_string(string):
		return
	return bandit.Issue(
		severity=bandit.MEDIUM,
		confidence=bandit.MEDIUM,
		text="Possible SQL injection vector through format string based "
			 "query construction."
	)

@test.checks('Call')
@test.test_id('SS0100')
def dynamic_cmd_dispatch(context):
	call = context.node
	if not (isinstance(call.func, ast.Name) and call.func.id == 'getattr' and len(call.args) >= 2):
		return
	arg0, arg1 = call.args[:2]
	if not isinstance(arg0, ast.Name):
		return
	arg0 = arg0.id
	if not arg0 in ('os', 'popen2', 'subprocess'):
		return

	child = context.node; parent = s_utils.get_top_parent_node(child); name = child.args[1]
	assigns = s_utils.get_definition_nodes(parent, name, child, prune=False)
	print("node {0} assigned {1} times".format(name, len(assigns)))
	for idx, node in enumerate(assigns):
		print("  #{0:<3} L{1:<3} {2!r} {3!r}".format(idx, node.lineno, node, 'redacted'))

	confidence = bandit.MEDIUM
	if isinstance(arg1, ast.Str):
		arg1 = arg1.s
		if arg0 == 'os':
			if arg1[:5] in ('execl', 'execv', 'popen', 'spawn', 'syste'):
				confidence = bandit.HIGH
		elif arg0 == 'popen2':
			if arg1.lower().startswith('popen'):
				confidence = bandit.HIGH
		elif arg0 == 'subprocess':
			if arg1 in ('Popen', 'call', 'check_call', 'check_output'):
				confidence = bandit.HIGH
	return bandit.Issue(
		severity=bandit.HIGH,
		confidence=confidence,
		text="Retrieved a function through which os commands can be executed."
	)

@test.checks('Str')
@test.test_id('SS0200')
def raw_str_sql_expressions(context):
	str_node = context.node
	if isinstance(str_node.parent, ast.BinOp):
		# avoid duplicates findings with B9101
		return
	return _check_string_for_sql(context.node)

@test.checks('BinOp')
@test.test_id('SS0201')
def old_fmt_str_sql_expressions(context):
	binop_node = context.node
	if not (isinstance(binop_node.op, ast.Mod) and isinstance(binop_node.left, ast.Str)):
		return
	return _check_string_for_sql(binop_node.left)

@test.checks('Call')
@test.test_id('SS0202')
def new_fmt_str_sql_expressions(context):
	call_node = context.node
	if not isinstance(call_node.func, ast.Attribute):
		return
	if not (call_node.args or getattr(call_node, 'kwargs', None)):
		return
	if not (isinstance(call_node.func.value, ast.Str) and call_node.func.attr == 'format'):
		return
	return _check_string_for_sql(call_node.func.value)

@test.checks('Call')
@test.test_id('SS0300')
def ftplib_auth_literal(context):
	username = None
	password = None
	call_node = context.node
	parent = s_utils.get_top_parent_node(call_node)
	if re.match(r'ftplib.FTP(_TLS)?', context.call_function_name_qual) is not None:
		username = next(s_utils.get_call_arg_values(parent, call_node, arg=1, kwarg='user'), None)
		password = next(s_utils.get_call_arg_values(parent, call_node, arg=2, kwarg='passwd'), None)
	elif isinstance(call_node.func, ast.Attribute) and call_node.func.attr == 'login':
		klass_name = next((klass for klass in s_utils.iter_method_classes(parent, call_node) if klass in ('ftplib.FTP', 'ftplib.FTP_TLS')), None)
		if klass_name is None:
			return
		username = next(s_utils.get_call_arg_values(parent, call_node, arg=0, kwarg='user'), None)
		password = next(s_utils.get_call_arg_values(parent, call_node, arg=1, kwarg='passwd'), None)
	return s_utils.report_hardcoded_credentials('ftplib', username, password)


@test.checks('Call')
@test.test_id('SS0301')
def smtplib_auth_literal(context):
	username = None
	password = None
	call_node = context.node
	parent = s_utils.get_top_parent_node(call_node)
	if isinstance(call_node.func, ast.Attribute) and call_node.func.attr == 'login':
		klass_name = next((klass for klass in s_utils.iter_method_classes(parent, call_node, import_aliases=context._context['import_aliases']) if klass in ('smtplib.SMTP', 'smtplib.SMTP_SSL')), None)
		if klass_name is None:
			return
		username = next(s_utils.get_call_arg_values(parent, call_node, arg=0, kwarg='user'), None)
		password = next(s_utils.get_call_arg_values(parent, call_node, arg=1, kwarg='password'), None)

	return s_utils.report_hardcoded_credentials('smtplib', username, password)
