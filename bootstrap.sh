#!/bin/bash -xe
pip install pip\>=8.0.0
pip install -r dev-requirements.txt
python setup.py develop
