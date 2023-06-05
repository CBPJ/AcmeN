import enum

__all__ = ['SupportedCA', 'AcmeAction', 'KeyType', 'KeyGenerationMethod', 'RevocationReason']


class SupportedCA(enum.Enum):
    LETSENCRYPT = 'https://acme-v02.api.letsencrypt.org/directory'
    BUYPASS = 'https://api.buypass.com/acme/directory'
    ZEROSSL = 'https://acme.zerossl.com/v2/DV90'
    LETSENCRYPT_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'
    BUYPASS_STAGING = 'https://api.test4.buypass.no/acme/directory'


class AcmeAction(enum.Enum):
    NewNonce = enum.auto()
    NewAccount = enum.auto()
    NewOrder = enum.auto()
    NewAuthz = enum.auto()
    RevokeCertByAccountKey = enum.auto()
    RevokeCertByCertKey = enum.auto()
    KeyChangeInner = enum.auto()
    # This is used by sign_request function to distinguish two sign processes in the keyChange action.
    KeyChangeOuter = enum.auto()
    VariableUrlAction = enum.auto()


class KeyType(enum.Enum):
    ECC384 = enum.auto()
    ECC256 = enum.auto()
    RSA4096 = enum.auto()
    RSA3072 = enum.auto()
    RSA2048 = enum.auto()


class KeyGenerationMethod(enum.Enum):
    CryptographyLib = enum.auto()
    OpenSSLCLI = enum.auto()


class RevocationReason(enum.IntEnum):
    Unspecified = 0
    KeyCompromise = 1
    AffiliationChanged = 3
    Superseded = 4
    CessationOfOperation = 5