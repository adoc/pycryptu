import logging
import hashlib

logger = logging.getLogger(__name__)


# Just some simple Py3/Py2 cross-compat.
try:
    range = xrange # For python < 3.0
except NameError:
    pass


class HashlibAdapter(object):
    def __init__(self, alg):
        self._alg_cls = alg

    def new(self, data=None):
        if data:
            return self._alg_cls(data)
        else:
            return self._alg_cls()

try:
    import Crypto.Hash
except ImportError:
    sha1 = HashlibAdapter(hashlib.sha1)
    sha512 = HashlibAdapter(hashlib.sha512)
    sha256 = HashlibAdapter(hashlib.sha256)
else:
    sha1 = Crypto.Hash.SHA1
    sha512 = Crypto.Hash.SHA512
    sha256 = Crypto.Hash.SHA256


# !!! Warning: Changing any of these might break any hashes across ANY
#              applications using this lib.
HASH_DEFAULT_REPETITIONS = 100
HASH_REPETITION_OMIT = 10
HASH_DEFAULT_PREALG = sha1
HASH_DEFAULT_ALG = sha512


try:
    import itsdangerous
except ImportError:
    logger.warning("Itsdangerous modeul is unavailable."
                "`codalib.crypto.TimedSerializer` will not be available.")
else:
    class TimedSerializer(itsdangerous.URLSafeTimedSerializer):
        """Shortcut to a slightly stronger itsdangerous.URLSafeTimedSerializer."""
        def __init__(self, key, namespace):
            itsdangerous.URLSafeTimedSerializer.__init__(key, salt=namespace,
                            signer_kwargs={'key_derivation':'hmac',
                                           'digest_method':sha256})


def shash(*values, **kwa):
    """Repetitively hash the `values` list.
    """
    repetitions = kwa.get('repetitions', HASH_DEFAULT_REPETITIONS)
    omit = kwa.get('omit', HASH_REPETITION_OMIT)
    prealg = kwa.get('prealg', HASH_DEFAULT_PREALG)
    alg = kwa.get('alg', HASH_DEFAULT_ALG)


    _hash = alg.new()

    def prehash(nonce):
        _prealg = prealg.new()
        for v in values:
            _prealg.update(v)
        _prealg.update(nonce)
        return _prealg

    for i in range(repetitions):
        if i % omit:
            _hash.update(prehash(_hash.digest()).digest())
        _hash.update(_hash.digest())

    return _hash