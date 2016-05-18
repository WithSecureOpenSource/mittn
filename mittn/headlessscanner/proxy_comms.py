"""Helper functions to communicate with Burp Suite extension.

Burp and Burp Suite are trademarks of Portswigger, Ltd.

"""
import select
import json
import shlex
import subprocess
import time

__copyright__ = "Copyright (c) 2013- F-Secure"


def read_next_json(process):
    """Return the next JSON formatted output from Burp Suite as a Python object."""
    # We will wait on Burp Suite's standard output
    pollobj = select.poll()
    pollobj.register(process.stdout, select.POLLIN)
    jsonobject = None  # Default to a failure
    while True:
        # Wait for max. 30 s, if timeout, return None.
        descriptors = pollobj.poll(30000)
        if descriptors == []:
            break
        # Read a line; if not JSON, continue polling with a new timeout.
        line = process.stdout.readline()
        if line == '':  # Burp Suite has exited
            break
        try:
            jsonobject = json.loads(line)
        except ValueError:
            continue
        break
    return jsonobject


def kill_subprocess(process):
    """Kill a subprocess, ignoring errors if it's already exited."""
    try:
        process.kill()
    except OSError:
        pass
    return


def start_burp(context):
    """Start Burp Suite as subprocess and wait for the extension to be ready."""
    burpcommand = shlex.split(context.burp_cmdline)
    burpprocess = subprocess.Popen(burpcommand, stdout=subprocess.PIPE)
    proxy_message = read_next_json(burpprocess)
    if proxy_message is None:
        kill_subprocess(burpprocess)
        assert False, "Starting Burp Suite and extension failed or timed out. Is extension output set as stdout? Command line was: %s" % context.burp_cmdline
    if proxy_message.get("running") != 1:
        kill_subprocess(burpprocess)
        assert False, "Burp Suite extension responded with an unrecognised JSON message"
    # In some cases, it takes some time for the proxy listener to actually
    # have an open port; I have been unable to pin down a specific time
    # so we just wait a bit.
    time.sleep(5)
    return burpprocess