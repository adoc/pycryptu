"""
"""
import sys
import logging


__py3__ = sys.version_info[0] is 3


logger = logging.getLogger(__name__)


URANDOM_ENTROPY_FACTOR = 1

# Random function.
try:
    from Crypto import Random
except ImportError:
    logger.warning("Crypto module is unavailable. `crypto_random` will"
                    "be slow")
    import os
    import math
    import cryptu.hash
    def read(length, hashalg=cryptu.hash.sha256.new):
        # Don't use for greater than 10,000 bytes.
        def gen():
            for i in range(int(math.ceil(length/hashalg().digest_size))):
                rnd = os.urandom(length*URANDOM_ENTROPY_FACTOR) # for attempted entropy.
                yield hashalg(rnd).digest()
        if __py3__:
            return b''.join(gen())[:length]
        else:
            return ''.join(gen())[:length]
else:
    read = Random.new().read