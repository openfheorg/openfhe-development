"""Analytical Hermite models from the paper and the private experiment scripts.

Inputs are centered integer LUT values; coefficients normalize by p. BKSS and
BKSS_NEW deliberately share the original first-order AKP/BKSS threshold model.
"""
import math

import numpy as np


def lut_values(name, p):
    x = np.arange(p)
    if name == "ID":
        return np.where(x > p // 2, x - p, x).astype(float)
    if name == "MSB":
        return np.where(x < p // 2, 0, p / 2)
    if name == "LSB":
        return (x % 2) * (p / 2)
    if name == "AES_SBox" and p == 256:
        values = np.array(AES_SBOX)
        return np.where(values > p // 2, values - p, values).astype(float)
    raise ValueError(f"Unsupported LUT {name}, p={p}")


def coefficients(values, order, method):
    """Power-basis coefficients; AKP/Sparse-THI require 2*Re on evaluation."""
    p = len(values)
    if p < 4 or p & (p - 1) or order < 1:
        raise ValueError("Require power-of-two p >= 4 and positive order")
    f = np.fft.fft(values) / p / p
    if method in ("SPARSE_THI", "FULL_THI"):
        last = p // 2 if method == "SPARSE_THI" else p - 1
        c = np.zeros(order * p + last + 1, dtype=complex)
        if method == "SPARSE_THI":
            f[0] = f[0].real / 2
            f[p // 2] = f[p // 2].real / 2
        for k in range(last + 1):
            for ell in range(order + 1):
                weight = math.prod((j + k / p) / (j - ell) for j in range(order + 1) if j != ell)
                c[ell * p + k] = weight * f[k]
        return c
    if method != "AKP" or order not in (1, 2, 3):
        raise ValueError(f"Unsupported polynomial {method}, order {order}")
    c = np.zeros((p if order == 1 else p + p // 2 + 1 if order == 2 else 2 * p), dtype=complex)
    c[:p] = (p - np.arange(p)) / p * f
    c[0] /= 2
    if order == 2:
        for k in range(1, p // 2 + 1):
            factor = (1 if k == p // 2 else 2) * k * (p - k) / (2 * p * p)
            c[k] += factor * f[k]
            c[p - k] -= factor * f[p - k] / 2
            c[p + k] -= factor * f[k] / 2
    if order == 3:
        for k in range(1, p):
            factor = k * (p - k) * (2 * p - k) / (3 * p**3)
            c[k] += factor * f[k]
            c[p - k] -= factor * f[p - k] / 2
            c[p + k] -= factor * f[k] / 2
    return c


def threshold(values, order, method, full_packing=False):
    """log2 T, preserving the original complex/full-packing 0.5/order correction."""
    p = len(values)
    if method in ("BKSS", "BKSS_NEW", "BKSS_LEGACY"):
        if order != 1:
            raise ValueError("BKSS only supports order 1")
        method = "AKP"
    if method == "AKP":
        c = coefficients(values, order, method)
        weighted = c * (2j * np.pi * np.arange(len(c))) ** (order + 1) / math.factorial(order + 1)
        folded = np.zeros(p, dtype=complex)
        np.add.at(folded, np.arange(len(c)) % p, weighted)
        maximum = np.max(np.abs((np.fft.ifft(folded) * p).real))
        result = -(1 + math.log2(maximum)) / order
    elif method in ("SPARSE_THI", "FULL_THI"):
        f = np.fft.fft(values) / p / p
        end = p // 2 + 1 if method == "SPARSE_THI" else p
        if method == "SPARSE_THI":
            f[p // 2] /= 2
        weighted = np.zeros(p, dtype=complex)
        for k in range(1, end):
            weight = math.gamma(order + 1 + k / p) / (math.gamma(order + 2) * math.gamma(k / p))
            weighted[k] = f[k] * weight
        maximum = np.max(np.abs(np.fft.ifft(weighted) * p))
        result = -(1 + 1 / order) * math.log2(2 * math.pi * p)
        result -= (math.log2(maximum) + (1 if method == "SPARSE_THI" else 0)) / order
    else:
        raise ValueError(method)
    return result - (0.5 / order if full_packing else 0)


def capacity(log_t, log_b, order):
    """Equations (4)–(5): log I, noise at I, and capacity in bits."""
    log_i = (log_b + order * log_t - math.log2(order)) / (order + 1)
    log_output = math.log2(1 + 1 / order) + log_b
    return log_i, log_output, log_i - log_output


TABLE3_ROWS = (("ID", 4), ("ID", 16), ("ID", 256), ("AES_SBox", 256),
               ("MSB", 256), ("LSB", 256), ("ID", 1024))


AES_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
