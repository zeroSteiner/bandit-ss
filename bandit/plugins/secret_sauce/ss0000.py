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
		klass_name = next(
			(klass for klass in s_utils.iter_method_classes(parent, call_node, import_aliases=context._context['import_aliases']) if klass in ('ftplib.FTP', 'ftplib.FTP_TLS')),
			None
		)
		if klass_name is None:
			return
		username = next(s_utils.get_call_arg_values(parent, call_node, arg=0, kwarg='user'), None)
		password = next(s_utils.get_call_arg_values(parent, call_node, arg=1, kwarg='passwd'), None)
	return s_utils.report_hardcoded_credentials('ftplib', username, password)

@test.checks('Call')
@test.test_id('SS0301')
def smtplib_auth_literal(context):
	call_node = context.node
	if not (isinstance(call_node.func, ast.Attribute) and call_node.func.attr == 'login'):
		return
	return s_utils.report_method_auth_literal(
		'smtplib',
		context,
		(0, 'user'),
		(1, 'password'),
		('smtplib.SMTP', 'smtplib.SMTP_SSL')
	)

@test.checks('Str')
@test.test_id('SS0302')
def basic_auth_literal(context):
	str_node = context.node
	if re.match(r'^basic\s+', str_node.s, flags=re.IGNORECASE) is None:
		return
	issue = bandit.Issue(
		severity=bandit.HIGH,
		confidence=bandit.MEDIUM,
		text='A hard-coded string is being used as an HTTP basic authorization header'
	)
	if re.match(r'^basic\s+[\w]{2,}={0,2}$', str_node.s, flags=re.IGNORECASE):
		return issue
	if not isinstance(str_node.parent, ast.BinOp):
		return
	binop_node = str_node.parent
	if not (isinstance(binop_node.op, (ast.Add, ast.Mod)) and binop_node.left == str_node):
		return
	parent = s_utils.get_top_parent_node(context.node)
	header_value = None
	if isinstance(binop_node.right, ast.Call):
		call_name = b_utils.get_call_name(binop_node.right, context._context['import_aliases'])
		if re.match(r'base64.(standard_|urlsafe_)?b64encode', call_name) is None:
			return
		header_value = next((value for value in s_utils.get_call_arg_values(parent, binop_node.right, arg=0) if isinstance(value, (str, bytes))), None)
	elif isinstance(binop_node.right, (ast.Name, ast.Str)):
		header_value = next((value for value in s_utils.iter_expr_literal_values(parent, binop_node.right) if isinstance(value, (str, bytes))), None)
	if header_value is None:
		return
	return issue
