from setuptools import setup, find_packages

setup(
    name="MoD",
    version="3.0.0",
    description="Master of Defense - Advanced Web Penetration Testing Tool",
    author="MoD Security Team",
    packages=find_packages(),
    install_requires=[
        "PyQt6>=6.6.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "dnspython>=2.4.0",
        "pyjwt>=2.8.0",
        "websocket-client>=1.6.0",
        "reportlab>=4.0.0",
        "Jinja2>=3.1.0",
    ],
    python_requires=">=3.8",
)