from setuptools import setup, find_packages

setup(
    name='LogManticsAI',
    version='0.1.0',
    description='LLM-Powered Log Analysis Tool',
    author='LogManticsAI',
    author_email='',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'agno>=1.5.0',
        'click>=8.1.7',
        'openai>=1.10.0',
        'python-dotenv>=1.0.0',
        'configparser>=6.0.0',
        'keyring>=24.2.0',
        'watchdog>=3.0.0',
        'slack-sdk>=3.25.0',
    ],
    entry_points={
        'console_scripts': [
            'LogManticsAI-init=LogManticsAI.main:tool_setup_command',
            'LogManticsAI-monitor=LogManticsAI.main:tail_and_analyze_command',
            'LogManticsAI-config=LogManticsAI.main:config_command',
            'LogManticsAI=LogManticsAI.main:cli',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: System :: Logging',
        'Topic :: System :: Monitoring',
    ],
    python_requires='>=3.8',
) 