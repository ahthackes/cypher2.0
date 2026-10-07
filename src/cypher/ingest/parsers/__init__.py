from cypher.ingest.parsers.auth import AuthLogParser
from cypher.ingest.parsers.syslog import SyslogParser
from cypher.ingest.parsers.webaccess import WebAccessParser

PARSERS_BY_SOURCE = {
    "auth_log": AuthLogParser,
    "syslog": SyslogParser,
    "web_access_log": WebAccessParser,
}

__all__ = ["AuthLogParser", "SyslogParser", "WebAccessParser", "PARSERS_BY_SOURCE"]
