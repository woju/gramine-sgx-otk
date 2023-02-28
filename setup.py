import setuptools

setuptools.setup(
    name='graminelibos_otk',
    version='0.1',
    install_requires='Click',
    author='Wojtek Porczyk',
    author_email = 'woju@invisiblethingslab.com',
    packages=setuptools.find_packages(),

    entry_points={
        'console_scripts': [
            'gramine-sgx-otk = graminelibos_otk.__main__:cli',
        ],
        'gramine.sgx_sign': [
            'otk = graminelibos_otk.signer:sign_with_otk',
        ],
    }
)
