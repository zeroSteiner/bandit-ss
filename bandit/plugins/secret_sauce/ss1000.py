import ast
import re

import bandit
from bandit.core import test_properties as test
from bandit.core import utils as b_utils

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
