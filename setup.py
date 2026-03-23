from setuptools import setup, find_packages

setup(
    name="crecon",
    version="0.1.0",
    author="Abhracodec",
    description="Automated recon toolkit for Linux",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.4.0",
        "paramiko>=3.3.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "crecon=crecon.cli:main",
        ],
    },
    python_requires=">=3.10",
)