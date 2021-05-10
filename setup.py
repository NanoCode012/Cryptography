## Run with: python setup.py build_ext --inplace

from setuptools import setup
from Cython.Build import cythonize
from shutil import copyfile, move
import glob, os, platform

file_names = [
    "AES/aes.py",
    "RSA/rsa.py",
    "util/parser.py",
]

# Slow for linux. Only do for Windows
if platform.system() == "Windows":
    file_names.append("util/prime.py")

for file_name in file_names:
    file_name_c = file_name[:-3] + "_c.pyx"
    copyfile(file_name, file_name_c)

    setup(
        ext_modules=cythonize(file_name_c, compiler_directives={"language_level": "3"})
    )

for file_name in file_names:
    # get path except file
    path = os.path.sep.join(file_name.split("/")[:-1])
    name = os.path.splitext(os.path.basename(file_name))[0]

    for pyd_file in glob.glob(f"{name}*.pyd"):
        src = pyd_file
        dst = os.path.join(path, pyd_file)
        move(src, dst)

    for so_file in glob.glob(os.path.join("build", "lib*", f"{name}*.so")):
        src = so_file
        dst = os.path.join(path, os.path.basename(src))
        move(src, dst)

