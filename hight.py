BITS = 7


def tint(x):
    return int(x.encode().hex(), 16)


def make_WK(K):
    WK = []
    for i in range(4):
        WK.append(K[i + 12])
    for i in range(4, 8):
        WK.append(K[i - 4])
    return WK


def make_SK(K):
    SK = []
    s = [0, 1, 0, 1, 1, 0, 1]
    delta = []
    delta.append("".join(str(s[i]) for i in range(6, -1, -1)))

    for i in range(1, 128):
        s.append(s[i + 2 - 1] ^ s[i - 1 - 1])
        delta.append("".join(str(s[j]) for j in range(i + 6, i - 1, -1)))

    for i in range(8):
        for j in range(8):
            SK.append((tint(K[(j - i) % 8]) + int(delta[16 * i + j], 2)) % (2**BITS))
        for j in range(8):
            SK.append(
                (tint(K[((j - i) % 8) + 8]) + int(delta[16 * i + j + 8], 2)) % (2**BITS)
            )
    return SK


def rol(val, i_bits, max_bits=BITS):
    return ((val << i_bits) & (2**max_bits - 1)) | (val >> (max_bits - i_bits))


def F0(x):
    return rol(x, 1) ^ rol(x, 2) ^ rol(x, 7)


def F1(x):
    return rol(x, 3) ^ rol(x, 4) ^ rol(x, 6)


def hight_enc(P, K):
    WK = make_WK(K)
    SK = make_SK(K)
    X = []

    X_tmp = []
    X_tmp.append((tint(P[0]) + tint(WK[0])) % (2**BITS))
    X_tmp.append(tint(P[1]))
    X_tmp.append(tint(P[2]) ^ tint(WK[1]))
    X_tmp.append(tint(P[3]))
    X_tmp.append((tint(P[4]) + tint(WK[2])) % (2**BITS))
    X_tmp.append(tint(P[5]))
    X_tmp.append(tint(P[6]) ^ tint(WK[3]))
    X_tmp.append(tint(P[7]))
    X.append(X_tmp)

    for i in range(31):
        X_tmp = []
        X_tmp.append(X[-1][7] ^ ((F0(X[-1][6]) + SK[4 * i + 3]) % (2**BITS)))
        X_tmp.append(X[-1][0])
        X_tmp.append((X[-1][1] + ((F1(X[-1][0]) ^ SK[4 * i]))) % (2**BITS))
        X_tmp.append(X[-1][2])
        X_tmp.append(X[-1][3] ^ ((F0(X[-1][2]) + SK[4 * i + 1]) % (2**BITS)))
        X_tmp.append(X[-1][4])
        X_tmp.append((X[-1][5] + ((F1(X[-1][4]) ^ SK[4 * i + 2]))) % (2**BITS))
        X_tmp.append(X[-1][6])
        X.append(X_tmp)

    X_tmp = []
    X_tmp.append(X[31][0])
    X_tmp.append((X[31][1] + (F1(X[31][0]) ^ SK[124])) % (2**BITS))
    X_tmp.append(X[31][2])
    X_tmp.append(X[31][3] ^ ((F0(X[31][2]) + SK[125]) % (2**BITS)))
    X_tmp.append(X[31][4])
    X_tmp.append((X[31][5] + (F1(X[31][4]) ^ SK[126])) % (2**BITS))
    X_tmp.append(X[31][6])
    X_tmp.append(X[31][7] ^ ((F0(X[31][6]) + SK[127]) % (2**BITS)))
    X.append(X_tmp)

    C = []
    C.append((X[32][0] + tint(WK[4])) % (2**BITS))
    C.append(X[32][1])
    C.append(X[32][2] ^ tint(WK[5]))
    C.append(X[32][3])
    C.append((X[32][4] + tint(WK[6])) % (2**BITS))
    C.append(X[32][5])
    C.append(X[32][6] ^ tint(WK[7]))
    C.append(X[32][7])

    C_str = "".join(chr(x) for x in C)
    return C_str


def hight_dec(C, K):
    WK = make_WK(K)
    SK = make_SK(K)
    X = []

    X_tmp = []
    X_tmp.append((tint(C[0]) - tint(WK[4])) % (2**BITS))
    X_tmp.append(tint(C[1]))
    X_tmp.append(tint(C[2]) ^ tint(WK[5]))
    X_tmp.append(tint(C[3]))
    X_tmp.append((tint(C[4]) - tint(WK[6])) % (2**BITS))
    X_tmp.append(tint(C[5]))
    X_tmp.append(tint(C[6]) ^ tint(WK[7]))
    X_tmp.append(tint(C[7]))
    X.append(X_tmp)

    X_tmp = []
    X_tmp.append(X[0][0])
    X_tmp.append((X[0][1] - (F1(X[0][0]) ^ SK[124])) % (2**BITS))
    X_tmp.append(X[0][2])
    X_tmp.append(X[0][3] ^ ((F0(X[0][2]) + SK[125]) % (2**BITS)))
    X_tmp.append(X[0][4])
    X_tmp.append((X[0][5] - (F1(X[0][4]) ^ SK[126])) % (2**BITS))
    X_tmp.append(X[0][6])
    X_tmp.append(X[0][7] ^ ((F0(X[0][6]) + SK[127]) % (2**BITS)))
    X.append(X_tmp)

    for i in range(30, -1, -1):
        X_tmp = []
        X_tmp.append(X[-1][1])
        X_tmp.append((X[-1][2] - (F1(X[-1][1]) ^ SK[4 * i])) % (2**BITS))
        X_tmp.append(X[-1][3])
        X_tmp.append(X[-1][4] ^ ((F0(X[-1][3]) + SK[4 * i + 1]) % (2**BITS)))
        X_tmp.append(X[-1][5])
        X_tmp.append((X[-1][6] - (F1(X[-1][5]) ^ SK[4 * i + 2])) % (2**BITS))
        X_tmp.append(X[-1][7])
        X_tmp.append(X[-1][0] ^ ((F0(X[-1][7]) + SK[4 * i + 3]) % (2**BITS)))
        X.append(X_tmp)

    P = []
    P.append((X[32][0] - tint(WK[0])) % (2**BITS))
    P.append(X[32][1])
    P.append(X[32][2] ^ tint(WK[1]))
    P.append(X[32][3])
    P.append((X[32][4] - tint(WK[2])) % (2**BITS))
    P.append(X[32][5])
    P.append(X[32][6] ^ tint(WK[3]))
    P.append(X[32][7])

    P_str = "".join(chr(x) for x in P)
    return P_str


P = "passw0rd"
print(P)
P_int = [ord(c) for c in P]
print(P_int)

K = "abcdefghijklmnop"

C = hight_enc(P, K)
print(C)
C_int = [ord(c) for c in C]
print(C_int)

P_dec = hight_dec(C, K)
print(P_dec)
P_dec_int = [ord(c) for c in P_dec]
print(P_dec_int)
