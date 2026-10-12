class DBPError(Exception): pass
class FrameError(DBPError): pass
class RecordError(DBPError): pass
class ReplayError(DBPError): pass
class StateError(DBPError): pass
class AuthorityError(DBPError): pass
class ResourceLimitError(DBPError): pass
