# backend/setup.py
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="threatshield-backend",
    version="1.0.0",
    author="ThreatShield Team",
    author_email="contact@threatshield.ai",
    description="Production-ready cyber defense platform with 5 research contributions",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/threatshield/platform",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "sgx": [
            "sgx-detect>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "threatshield=api.main:main",
            "threatshield-train=ai_models.train:main",
        ],
    },
    include_package_data=True,
)