from setuptools import find_packages, setup

with open("README.md") as fh:
    long_description = fh.read()


requirements = ["smda>=4.2.13"]


setup(
    name="picblocks",
    version="2.0.2",
    description="A library for code similarity estimation using PIC hashing over basic blocks.",
    long_description_content_type="text/markdown",
    long_description=long_description,
    author="Daniel Plohmann",
    author_email="daniel.plohmann@mailbox.org",
    url="https://github.com/danielplohmann/picblocks",
    license="BSD 2-Clause",
    packages=find_packages(exclude=("tests")),
    data_files=[
        ("", ["LICENSE"]),
    ],
    install_requires=requirements,
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Disassemblers",
    ],
    python_requires=">=3.8",
)
