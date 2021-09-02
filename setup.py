from setuptools import find_packages, setup


setup(
    name="neuro-admin-client",
    python_requires=">=3.8",
    url="https://github.com/neuro-inc/neuro-admin-client",
    packages=find_packages(),
    setup_requires=["setuptools_scm"],
    install_requires=[
        "aiohttp>=3.7",
    ],
    use_scm_version=True,
    include_package_data=True,
)
