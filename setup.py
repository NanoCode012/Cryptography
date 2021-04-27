## Run with: python setup.py build_ext --inplace

from setuptools import setup
from Cython.Build import cythonize
from shutil import copyfile, move
import glob, os

file_names = ['util/aes.py', 'util/rsa.py']

for file_name in file_names:
    file_name_c =  file_name[:-3] + '_c.pyx'
    copyfile(file_name, file_name_c)

    setup(
        ext_modules = cythonize(
            file_name_c,
            compiler_directives={'language_level' : "3"}
            )
    )

for file_name in glob.glob('*.pyd'):
    move(file_name, os.path.join(f'util/{file_name}'))

