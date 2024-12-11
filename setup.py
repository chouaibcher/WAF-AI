from setuptools import setup, find_packages

setup(
    name='WAF-AI',                     # Nom de la bibliothèque
    version='0.1.0',                       # Version
    packages=find_packages(),              # Recherche automatique des packages
    install_requires=['flask',
                      'django',
                      'numpy'
                      ],                   # Dépendances
    description='Web application firewall using AI',
    include_package_data=True, 
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='CHERIBET CHERIF CHOUAIB',
    author_email='chouaibcher@gmail.com',
    url='https://github.com/chouaibcher/WAF-AI',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],


    python_requires='>=3.6',
)
