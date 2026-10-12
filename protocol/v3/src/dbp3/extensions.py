from enum import Enum
class RegistryStatus(str,Enum): REQUIRED='required'; PREFERRED='preferred'; OPTIONAL='optional'; DEPRECATED='deprecated'; FORBIDDEN='forbidden'; EXPERIMENTAL='experimental'
def extension_range(type_id:int)->str:
    if 1<=type_id<=255: return 'core'
    if type_id<=4095: return 'standards-extension'
    if type_id<=32767: return 'application'
    if type_id<=49151: return 'experimental'
    if type_id<=65535: return 'vendor-private'
    raise ValueError('type id')
