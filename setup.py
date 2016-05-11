from setuptools import setup, find_packages


setup(
    name='mittn',
    use_scm_version=True,
    description='Security test suite',
    long_description='',
    classifiers=[
          "Programming Language :: Python :: 2.7"
          "Programming Language :: Python :: 3.4"
    ],
    author='F-Secure Corporation',
    author_email='opensource@f-secure.com',
    url='https://github.com/F-Secure/mittn',
    packages=find_packages(),
    #package_data={'mittn': ['*.rc']},
    install_requires=open('requirements.txt').readlines(),
)
