import ast
import itertools
import re

import bandit
from bandit.core import test_properties as test
from bandit.core import utils as b_utils

from . import taintable
from . import utils as s_utils

SUBPROCESS = {
    'commands': (
        'getoutput',
        'getstatusoutput'
    ),
    'os': (
        'system',
        'popen',
        'popen2',
        'popen3',
        'popen4',
        'execl',
        'execle',
        'execlp',
        'execlpe',
        'execv',
        'execve',
        'execvp',
        'execvpe',
        'spawnl',
        'spawnle',
        'spawnlp',
        'spawnlpe',
        'spawnv',
        'spawnve',
        'spawnvp',
        'spawnvpe',
        'startfile'
    ),
    'popen2': (
        'popen2',
        'popen3',
        'popen4',
        'Popen3',
        'Popen4'
    ),
    'subprocess': (
        'Popen',
        'call',
        'check_call',
        'check_output'
    )
}


def _check_string_for_sql(ast_str, confidence=None, severity=None):
    string = ast_str.s
    if not _looks_like_sql_string(string):
        return
    return bandit.Issue(
        confidence=confidence or bandit.MEDIUM,
        severity=severity or bandit.MEDIUM,
        text="Possible SQL injection vector through format string based "
             "query construction."
    )


def _looks_like_sql_string(data):
    val = data.lower().lstrip()
    return ((val.startswith('select ') and ' from ' in val) or
            val.startswith('insert into') or
            (val.startswith('update ') and ' set ' in val) or
            val.startswith('delete from '))


@test.checks('Call')
@test.test_id('SS0100')
def dynamic_cmd_dispatch(context):
    call_node = context.node
    if not (isinstance(call_node.func, ast.Name) and call_node.func.id == 'getattr' and len(call_node.args) >= 2):
        return
    arg0, arg1 = call_node.args[:2]
    if not isinstance(arg0, ast.Name):
        return
    arg0 = context._context['import_aliases'].get(arg0.id, arg0.id)
    methods = SUBPROCESS.get(arg0)
    if methods is None:
        return
    confidence = bandit.LOW
    arg1_values = tuple(s_utils.iter_expr_literal_values(s_utils.get_top_parent_node(context.node), arg1, child=call_node))
    if arg1_values:
        if all((name in methods for name in arg1_values)):
            confidence = bandit.HIGH
        elif any((name in methods for name in arg1_values)):
            confidence = bandit.MEDIUM
        else:
            return

    return bandit.Issue(
        severity=bandit.HIGH,
        confidence=confidence,
        text="Retrieved a function through which os commands can be executed."
    )


@test.checks('Call')
@test.test_id('SS0110')
def json_object_load_hook(context):
    if not context.call_function_name_qual in ('json.JSONDecoder', 'json.load', 'json.loads'):
        return
    object_hook = context.call_keywords.get('object_hook')
    if object_hook is None:
        return
    issue = bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.MEDIUM,
        text="A custom JSON object_hook '{0}' is being used to load data.".format(object_hook)
    )
    return issue


@test.checks('Str')
@test.test_id('SS0200')
def raw_str_sql_expressions(context):
    str_node = context.node
    if isinstance(str_node.parent, ast.BinOp):
        # avoid duplicates findings with B9101
        return
    return _check_string_for_sql(context.node, confidence=bandit.LOW)


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
        if not s_utils.method_could_be_class(call_node, context, ('ftplib.FTP', 'ftplib.FTP_TLS')):
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


@test.checks('Call')
@test.test_id('SS0302')
def basic_auth_literal(context):
    call_node = context.node
    parent = s_utils.get_top_parent_node(call_node)
    if not (isinstance(call_node.func, ast.Attribute) and call_node.func.attr == 'add_header'):
        return
    klass_name = next(
        (klass for klass in s_utils.iter_method_classes(parent, call_node, context) if klass in ('urllib2.Request', 'urllib.request.Request')),
        None
    )
    if klass_name is None:
        return
    if not len(call_node.args) == 2:
        return
    arg0, arg1 = call_node.args[:2]
    if not (isinstance(arg0, ast.Str) and arg0.s.lower() == 'authorization'):
        return
    if isinstance(arg1, ast.BinOp) and isinstance(arg1.left, ast.Str):
        str_node = arg1.left
        str_node.parent = arg1
    elif isinstance(arg1, ast.Str):
        str_node = arg1
    else:
        return

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


@test.checks('Call')
@test.test_id('SS0400')
def insecure_hashlib_new_algorithm(context):
    call_node = context.node
    if not (context.call_function_name_qual == 'hashlib.new' and len(call_node.args)):
        return
    arg0 = call_node.args[0]
    parent = s_utils.get_top_parent_node(call_node)
    insecure_algorithms = ('md2', 'md4', 'md5')
    confidence = None
    if isinstance(arg0, ast.Str) and arg0.s.lower() in insecure_algorithms:
        confidence = bandit.HIGH
    elif isinstance(arg0, ast.Name):
        algorithms = tuple(s_utils.iter_expr_literal_values(parent, arg0, call_node))
        if algorithms and all(algo.lower() in insecure_algorithms for algo in algorithms):
            confidence = bandit.HIGH
        elif algorithms and any(algo.lower() in insecure_algorithms for algo in algorithms):
            confidence = bandit.MEDIUM
    if confidence is None:
        return
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=confidence,
        text='Use of insecure MD2, MD4, or MD5 hash function.'
    )

@test.checks('Call')
@test.test_id('SS0500')
def traversal_via_tarfile_extractall(context):
    call_node = context.node
    if not isinstance(call_node.func, ast.Attribute):
        return
    if not isinstance(call_node.func.value, ast.Name):
        return
    name = s_utils.get_attribute_name(call_node.func)
    if not (name and name.endswith('.extractall')):
        return
    if not s_utils.method_could_be_class(call_node, context, ('tarfile.open',)):
        return
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.HIGH,
        text='Use of tarfile.extractall() can result in files being written to arbitrary locations on the file system.'
    )

@test.checks('Call')
@test.test_id('SS0501')
def traversal_via_shutil_unpack_archive(context):
    if context.call_function_name_qual != 'shutil.unpack_archive':
        return
    return bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.HIGH,
        text='Use of shutil.unpack_archive() can result in files being written to arbitrary locations on the file system.'
    )

@test.checks('Call')
@test.test_id('SS0502')
def traversal_via_http_request(context):
    if context.call_function_name_qual != 'open':
        return
    call_node = context.node
    parent = s_utils.search_node_parents(call_node, (ast.ClassDef, ast.FunctionDef, ast.Module))
    if not isinstance(parent, ast.FunctionDef):
        return
    method_node = parent
    parent = s_utils.search_node_parents(method_node, (ast.ClassDef, ast.Module))
    if not isinstance(parent, ast.ClassDef):
        return
    class_node = parent
    if re.match(r'^do_(DELETE|GET|HEAD|POST|PUT)$', method_node.name) is None:
        return
    if not s_utils.method_could_be_class(method_node, context, ('BaseHTTPServer.BaseHTTPRequestHandler', 'BaseHTTPServer.SimpleHTTPRequestHandler', 'http.server.BaseHTTPRequestHandler', 'http.server.SimpleHTTPRequestHandler')):
        return
    # at this point we strongly believe that this is a call to open in an HTTP
    # do_METHOD handler
    arg0_node = call_node.args[0]
    taint_node = None
    is_taint_target = lambda n: isinstance(n, ast.Attribute) and s_utils.get_attribute_name(n) == 'self.path'
    for node in ast.walk(arg0_node):
        if is_taint_target(node):
            taint_node = node
            break
        if not isinstance(node, ast.Name):
            continue
        for def_node in s_utils.get_definition_nodes(method_node, node, child=node):
            if not isinstance(def_node, ast.Assign):
                continue
            taint_node = next((n for n in ast.walk(def_node) if is_taint_target(n)), None)
            if taint_node is None:
                continue
            if taintable.TaintablePath(def_node, taint_node, context=context):
                taint_node = node
                break
        if taint_node:
            break
    if taint_node is None:
        return
    if not taintable.TaintablePath(call_node, taint_node, context=context):
        return
    return bandit.Issue(
        severity=bandit.HIGH,
        confidence=bandit.MEDIUM,
        text="Path traversal detected in HTTP method handler: {0}".format(method_node.name)
    )
