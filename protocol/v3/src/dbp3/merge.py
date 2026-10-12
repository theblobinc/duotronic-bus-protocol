from dataclasses import dataclass
@dataclass(frozen=True)
class AuthoritySnapshot:
    domain:str; sequence:int; revoked:frozenset[str]; witness_id:str
    def validate(self):
        if not self.domain or self.sequence<1 or not self.witness_id: raise ValueError('authority snapshot')
        return self

def merge_authority(left:AuthoritySnapshot,right:AuthoritySnapshot)->AuthoritySnapshot:
    left.validate(); right.validate()
    if left.domain != right.domain: raise ValueError('authority domain mismatch')
    # Revocation is monotone across partitions; chronology advances to max observed.
    seq=max(left.sequence,right.sequence)
    revoked=left.revoked | right.revoked
    wid=left.witness_id if left.sequence>=right.sequence else right.witness_id
    return AuthoritySnapshot(left.domain,seq,revoked,wid)
