import whois

from model.whois_model import WhoisRecord


class WhoisService:
    """Performs a WHOIS lookup on a domain and persists the result to the database."""

    def __init__(self, db_session):
        self.session = db_session

    def perform_whois(self, domain: str) -> WhoisRecord:
        data = whois.whois(domain)

        record = WhoisRecord(
            domain=domain,
            raw_data=self._safe_str(data),
            registrar=getattr(data, 'registrar', None),
            creation_date=self._first(getattr(data, 'creation_date', None)),
            expiration_date=self._first(getattr(data, 'expiration_date', None)),
        )

        self.session.add(record)
        self.session.commit()

        return record

    @staticmethod
    def _first(value):
        """python-whois sometimes returns a list of dates (history); we use the first one."""
        if isinstance(value, (list, tuple)):
            return value[0] if value else None
        return value

    @staticmethod
    def _safe_str(data) -> str:
        try:
            return str(data)
        except Exception:
            return ''
