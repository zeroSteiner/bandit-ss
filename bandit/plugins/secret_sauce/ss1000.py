import ast
import re

import bandit
from bandit.core import test_properties as test
from bandit.core import utils as b_utils
from six.moves import urllib

from . import eval_ast
from . import utils as s_utils

@test.checks('Call')
@test.test_id('SS1000')
def requests_auth_literal(context):
    if re.match(r'requests\.(get|head|post|put|)', context.call_function_name_qual) is None:
        return
    call_node = context.node
    kwarg_nodes = dict((kwarg.arg, kwarg.value) for kwarg in call_node.keywords)
    if 'auth' not in kwarg_nodes:
        return
    auth_value = context.call_keywords.get('auth')
    if auth_value is not None:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=(bandit.HIGH if (isinstance(auth_value, (list, tuple)) and len(auth_value) == 2) else bandit.MEDIUM),
            text="Hard-coded credentials are being passed to the requests library for basic authentication."
        )
    if not isinstance(kwarg_nodes['auth'], ast.Call):
        return
    arg_call = b_utils.get_call_name(kwarg_nodes['auth'], context._context['import_aliases'])
    if arg_call not in ('requests.HTTPBasicAuth', 'requests.HTTPDigestAuth'):
        return
    parent = s_utils.get_top_parent_node(call_node)
    username = next(s_utils.get_call_arg_values(parent, kwarg_nodes['auth'], arg=0, child=call_node), None)
    password = next(s_utils.get_call_arg_values(parent, kwarg_nodes['auth'], arg=1, kwarg='password', child=call_node), None)

    return s_utils.report_hardcoded_credentials('requests', username, password)


@test.checks('Call')
@test.test_id('SS1100')
def paramiko_auth_literal(context):
    call_node = context.node
    if not (isinstance(call_node.func, ast.Attribute) and call_node.func.attr == 'connect'):
        return
    return s_utils.report_method_auth_literal(
        'paramiko',
        context,
        (2, 'username'),
        (3, 'password'),
        ('paramiko.SSHClient',)
    )

@test.checks('Assign')
@test.test_id('SS1200')
def flask_sqlalchemy_auth_literal(context):
    assign_node = context.node
    if not assign_node.targets:
        return
    if not s_utils.node_targets_name(assign_node, 'SQLALCHEMY_DATABASE_URI'):
        return
    node = s_utils.get_expr_value_src_dst(assign_node.value, assign_node.targets[0], 'SQLALCHEMY_DATABASE_URI')
    if node is None:
        return
    success, value = eval_ast.literal_expr(node)
    if not (success and isinstance(value, str)):
        return
    parsed_uri = urllib.parse.urlparse(value)
    if re.match('^\w+:\w+@\w+$', parsed_uri.netloc) is None:
        return
    return bandit.Issue(
        confidence=bandit.HIGH,
        severity=bandit.HIGH,
        text="Hard-coded credentials are defined in Flasks SQLALCHEMY_DATABASE_URI option."
    )

@test.checks('Call')
@test.test_id('SS1300')
def msgpack_object_load_hook(context):
    if not context.call_function_name_qual in ('msgpack.Unpacker', 'msgpack.unpack', 'msgpack.unpackb'):
        return
    object_hook = context.call_keywords.get('object_hook')
    if object_hook is None:
        return
    issue = bandit.Issue(
        severity=bandit.MEDIUM,
        confidence=bandit.MEDIUM,
        text="A custom msgpack object_hook '{0}' is being used to load data.".format(object_hook)
    )
    return issue
