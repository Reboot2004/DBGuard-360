"""
Setup script for DBGurd 360
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="dbguard360",
    version="0.1.0",
    author="DBGuard Team",
    description="MySQL Database Protection System with Query Logging and Recovery",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/dbgurd-360",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Database",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "mysql-connector-python>=8.0.0",
        "click>=8.0.0",
    ],
    entry_points={
        "console_scripts": [
            "dbguard360=src.cli.commands:cli",
        ],
    },
)
