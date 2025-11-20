"""
Setup script for Network Scanner package.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network-scanner",
    version="1.0.0",
    author="Security Team",
    description="Professional network scanner for authorized security assessments",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/scanner-de-red",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "netscan=scanner.cli:main",
        ],
    },
    install_requires=[
        # No runtime dependencies - uses standard library only
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
        ],
    },
)
