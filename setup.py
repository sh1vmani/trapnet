from setuptools import setup, find_packages

with open("requirements.txt") as f:
    install_requires = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="trapnet",
    version="0.1.0",
    description="Async honeypot framework with 15 service emulators and attack detection",
    author="sh1vmani",
    license="MIT",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        "console_scripts": [
            "trapnet=trapnet.__main__:main",
        ],
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
