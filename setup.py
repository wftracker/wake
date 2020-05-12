import re
from setuptools import setup

version = ""
with open("wake/__init__.py") as fp:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]', fp.read(), re.MULTILINE).group(1)

readme = ""
with open("README.md") as fp:
    readme = fp.read()

setup(
    name="wake",
    version=version,
    author="Kavan72",
    url="https://github.com/Kavan72/wake",
    packages=["wake"],
    license="MIT",
    description="A basic encryption algorithms for the Warface's wake.",
    long_description=readme,
    long_description_content_type="text/markdown"
)
