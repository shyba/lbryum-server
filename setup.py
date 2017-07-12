from setuptools import setup, find_packages
from lbryumserver import __version__
import os
import sys

requires = [
    'plyvel==0.9',
    'jsonrpclib',
    'python-bitcoinrpc==0.1',
    'appdirs==1.4.3',
    'lbryschema==0.0.8',
]

if sys.platform == "darwin":
    os.environ['CFLAGS'] = "-mmacosx-version-min=10.7 -stdlib=libc++ -I/usr/local/Cellar/leveldb/1.20/include"
    os.environ['LDFLAGS'] = "-L/usr/local/Cellar/leveldb/1.20/lib"

base_dir = os.path.dirname(os.path.abspath(__file__))

setup(
    name="lbryum-server",
    packages=find_packages(base_dir, exclude=['tests']),
    version=__version__,
    entry_points={'console_scripts': ['lbryum-server = lbryumserver.main:main']},
    install_requires=requires,
    description="LBRY Electrum Server",
    author="Thomas Voegtlin",
    author_email="thomasv1@gmx.de",
    license="GNU Affero GPLv3",
    url="https://github.com/lbryio/lbryum-server/",
    long_description="""Server for the Electrum Lightweight LBRY Wallet"""
)
