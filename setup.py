from setuptools import setup, find_packages


setup(
    name='mittn',
    use_scm_version=True,
    description='Mittn',
    long_description=open('README.txt').read(),
    classifiers=[
          "Programming Language :: Python :: 2.7"
    ],
    license='Apache License 2.0',
    author='F-Secure Corporation',
    author_email='opensource@f-secure.com',
    url='https://github.com/F-Secure/mittn',
    packages=find_packages(exclude=['features']),
    install_requires=open('requirements.txt').readlines(),
)
