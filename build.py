import os
from setuptools import Extension
from Cython.Build import cythonize

# Define the C-Extension compilation for our secure cryptography module
extensions = [
    Extension(
        "ranbval_sdk.crypto",
        ["src/ranbval_sdk/crypto.py"],
    )
]

def build(setup_kwargs):
    """
    Hook for Poetry to compile the Python script into a raw C/C++ Shared Object (.so) Machine Code binary.
    """
    setup_kwargs.update({
        "ext_modules": cythonize(extensions, language_level=3, compiler_directives={'linetrace': False})
    })
