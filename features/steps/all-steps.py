# pylint: disable=E0602,E0102
from behave import *

# Import all step definitions for all the test tools.
from mittn.headlessscanner.steps import *
from mittn.tlschecker.steps import *
from mittn.httpfuzzer.steps import *

__copyright__ = "Copyright (c) 2013- F-Secure"
