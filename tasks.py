from invoke.collection import Collection
from wires.common.tasks.common import clean
from wires.python.tasks import py

ns = Collection(
    clean,
    py=Collection(py.start, py.stop, py.pep8, py.pylint, py.test, py.package, py.upload),
)
ns.configure({
    'run': {'echo': True},
    'project': 'push-sdk',
    'package': 'push',
    'package_dir': 'push',
})
