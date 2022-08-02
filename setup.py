from setuptools import setup

if __name__ == "__main__":
    try:
        setup(use_scm_version={"version_scheme": "no-guess-dev"}, install_requires=["cairo-lang==0.9.0", "cairo-nile==0.6.1", "starknet.py==0.3.1a0", "pytest==6.2.5", "pytest-asyncio==0.18.3"])
    except:  # noqa
        print(
            "\n\nAn error occurred while building the project, "
            "please ensure you have the most updated version of setuptools, "
            "setuptools_scm and wheel with:\n"
            "   pip install -U setuptools setuptools_scm wheel\n\n"
        )
        raise