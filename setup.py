from setuptools import setup

setup(
    name="lbryum-server",
    version="1.0",
    scripts=['run_lbryum_server.py','lbryum-server'],
    install_requires=['plyvel','jsonrpclib', 'irc>=11'],
    package_dir={
        'lbryumserver':'src'
        },
    py_modules=[
        'lbryumserver.__init__',
        'lbryumserver.utils',
        'lbryumserver.storage',
        'lbryumserver.deserialize',
        'lbryumserver.networks',
        'lbryumserver.blockchain_processor',
        'lbryumserver.server_processor',
        'lbryumserver.processor',
        'lbryumserver.version',
        'lbryumserver.ircthread',
        'lbryumserver.stratum_tcp',
        'lbryumserver.stratum_http'
    ],
    description="LBRY Electrum Server",
    author="Thomas Voegtlin",
    author_email="thomasv1@gmx.de",
    license="GNU Affero GPLv3",
    url="https://github.com/spesmilo/lbryum-server/",
    long_description="""Server for the Electrum Lightweight LBRY Wallet"""
)


