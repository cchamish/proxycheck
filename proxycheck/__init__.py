"""Proxy Detector project configuration package."""

try:
    import pymysql

    pymysql.install_as_MySQLdb()
except ImportError:
    pass
