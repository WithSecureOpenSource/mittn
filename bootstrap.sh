#!/bin/bash -xe
pip install pip\>=8.0.0
pip install -r dev-requirements.txt
(cd fuzzer && python setup.py develop)
(cd tls && python setup.py develop)
(cd scanner && python setup.py develop)
