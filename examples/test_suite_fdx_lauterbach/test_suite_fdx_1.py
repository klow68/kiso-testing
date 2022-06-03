##########################################################################
# Copyright (c) 2010-2022 Robert Bosch GmbH
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License 2.0 which is available at
# http://www.eclipse.org/legal/epl-2.0.
#
# SPDX-License-Identifier: EPL-2.0
##########################################################################

import logging

import pykiso
from pykiso.auxiliaries import fdx_aux


@pykiso.define_test_parameters(suite_id=1, aux_list=[fdx_aux])
class TestSuiteSetUp(pykiso.BasicTestSuiteSetup):
    pass


@pykiso.define_test_parameters(suite_id=1, case_id=1, aux_list=[fdx_aux])
class TestCase(pykiso.BasicTest):
    pass


@pykiso.define_test_parameters(suite_id=1, aux_list=[fdx_aux])
class TestSuiteTearDown(pykiso.BasicTestSuiteTeardown):
    pass
