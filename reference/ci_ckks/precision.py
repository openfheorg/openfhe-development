"""Global precision contract and shared mpmath constructors.

Every module imports its complex/real constructors and trig from here so no module
can accidentally leak a Python float (53-bit) into the math path.
"""
import mpmath

# Working precision in bits. 256 > the 200-bit floor in the plan, a round binary
# number so re-derivation is bit-stable. Recorded in every golden-JSON header.
MP_PREC_BITS = 256
mpmath.mp.prec = MP_PREC_BITS

# The universal acceptance threshold (plan §2/§4): two derivations of the CI DFT,
# and U·U^{-1}=I, must agree below this.
THRESHOLD = mpmath.mpf(2) ** -100


def set_precision(bits=MP_PREC_BITS):
    """Set (and return previous) global mpmath precision in bits."""
    prev = mpmath.mp.prec
    mpmath.mp.prec = bits
    return prev


def mpf(x):
    return mpmath.mpf(x)


def mpc(re, im=0):
    return mpmath.mpc(re, im)


def pi():
    return mpmath.pi


def cos(theta):
    return mpmath.cos(theta)


def sin(theta):
    return mpmath.sin(theta)


def exp_i(theta):
    """exp(i*theta) at full precision."""
    return mpmath.e ** (mpmath.mpc(0, 1) * theta)


def to_decimal_str(x, sig=85):
    """Serialize an mpf/mpc to a decimal string with >=80 significant digits so a
    256-bit value survives a JSON round-trip. Complex -> {'re':..,'im':..}."""
    if isinstance(x, mpmath.mpc) or isinstance(x, complex):
        xc = mpmath.mpc(x)
        return {"re": mpmath.nstr(xc.real, sig, strip_zeros=False),
                "im": mpmath.nstr(xc.imag, sig, strip_zeros=False)}
    return mpmath.nstr(mpmath.mpf(x), sig, strip_zeros=False)


def from_decimal(s):
    """Inverse of to_decimal_str."""
    if isinstance(s, dict):
        return mpmath.mpc(mpmath.mpf(s["re"]), mpmath.mpf(s["im"]))
    return mpmath.mpf(s)
