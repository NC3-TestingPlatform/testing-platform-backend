"""Scan-module plug-ins and the SDK they implement (US #76, IDR-007).

Everything under this package is plug-in territory: the contract the five M*
module stories code against (`contract`), the entry-point roster that makes
them discoverable (`registry`), and the modules themselves, one sub-package
each. The dependency arrow points one way — modules import platform
vocabulary from `core.enums`, and nothing in `core/`, `domains/`, or
`worker/` imports this package by name; discovery goes through the
`nc3_testing_platform.modules` entry-point group only, so adding a module
touches no core code. A test enforces the arrow.
"""

import logging

# Library-style hygiene for a plug-in surface: modules log under this
# namespace, and a host that configures no handler gets silence, not stderr.
logging.getLogger(__name__).addHandler(logging.NullHandler())
