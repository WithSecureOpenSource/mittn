from setuptools import setup, find_packages


setup(
    name='mittn-tls',
    use_scm_version={'root': '..'},
    description='Mittn TLS Checker',
    long_description='',
    classifiers=[
          "Programming Language :: Python :: 2.7"
          "Programming Language :: Python :: 3.4"
    ],
    license='Apache License 2.0',
    author='F-Secure Corporation',
    author_email='opensource@f-secure.com',
    url='https://github.com/F-Secure/mittn',
    packages=find_packages(),
    install_requires=open('requirements.txt').readlines(),
)
