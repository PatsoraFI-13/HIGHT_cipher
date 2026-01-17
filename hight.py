BITS = 7


def mod_sum(a, b):
    return (a + b) % (2**BITS)


def mod_sub(a, b):
    return (a - b) % (2**BITS)


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
            SK.append(mod_sum(K[(j - i) % 8], int(delta[16 * i + j], 2)))
        for j in range(8):
            SK.append(mod_sum(K[((j - i) % 8) + 8], int(delta[16 * i + j + 8], 2)))
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
    X_tmp.append(mod_sum(P[0], WK[0]))
    X_tmp.append(P[1])
    X_tmp.append(P[2] ^ WK[1])
    X_tmp.append(P[3])
    X_tmp.append(mod_sum(P[4], WK[2]))
    X_tmp.append(P[5])
    X_tmp.append(P[6] ^ WK[3])
    X_tmp.append(P[7])
    X.append(X_tmp)

    for i in range(31):
        X_tmp = []
        X_tmp.append(X[-1][7] ^ mod_sum(F0(X[-1][6]), SK[4 * i + 3]))
        X_tmp.append(X[-1][0])
        X_tmp.append(mod_sum(X[-1][1], (F1(X[-1][0]) ^ SK[4 * i])))
        X_tmp.append(X[-1][2])
        X_tmp.append(X[-1][3] ^ mod_sum(F0(X[-1][2]), SK[4 * i + 1]))
        X_tmp.append(X[-1][4])
        X_tmp.append(mod_sum(X[-1][5], (F1(X[-1][4]) ^ SK[4 * i + 2])))
        X_tmp.append(X[-1][6])
        X.append(X_tmp)

    X_tmp = []
    X_tmp.append(X[31][0])
    X_tmp.append(mod_sum(X[31][1], (F1(X[31][0]) ^ SK[124])))
    X_tmp.append(X[31][2])
    X_tmp.append(X[31][3] ^ mod_sum(F0(X[31][2]), SK[125]))
    X_tmp.append(X[31][4])
    X_tmp.append(mod_sum(X[31][5], (F1(X[31][4]) ^ SK[126])))
    X_tmp.append(X[31][6])
    X_tmp.append(X[31][7] ^ mod_sum(F0(X[31][6]), SK[127]))
    X.append(X_tmp)

    C = []
    C.append(mod_sum(X[32][0], WK[4]))
    C.append(X[32][1])
    C.append(X[32][2] ^ WK[5])
    C.append(X[32][3])
    C.append(mod_sum(X[32][4], WK[6]))
    C.append(X[32][5])
    C.append(X[32][6] ^ WK[7])
    C.append(X[32][7])

    return C


def hight_dec(C, K):
    WK = make_WK(K)
    SK = make_SK(K)
    X = []

    X_tmp = []
    X_tmp.append(mod_sub(C[0], WK[4]))
    X_tmp.append(C[1])
    X_tmp.append(C[2] ^ WK[5])
    X_tmp.append(C[3])
    X_tmp.append(mod_sub(C[4], WK[6]))
    X_tmp.append(C[5])
    X_tmp.append(C[6] ^ WK[7])
    X_tmp.append(C[7])
    X.append(X_tmp)

    X_tmp = []
    X_tmp.append(X[0][0])
    X_tmp.append(mod_sub(X[0][1], (F1(X[0][0]) ^ SK[124])))
    X_tmp.append(X[0][2])
    X_tmp.append(X[0][3] ^ mod_sum(F0(X[0][2]), SK[125]))
    X_tmp.append(X[0][4])
    X_tmp.append(mod_sub(X[0][5], (F1(X[0][4]) ^ SK[126])))
    X_tmp.append(X[0][6])
    X_tmp.append(X[0][7] ^ mod_sum(F0(X[0][6]), SK[127]))
    X.append(X_tmp)

    for i in range(30, -1, -1):
        X_tmp = []
        X_tmp.append(X[-1][1])
        X_tmp.append(mod_sub(X[-1][2], (F1(X[-1][1]) ^ SK[4 * i])))
        X_tmp.append(X[-1][3])
        X_tmp.append(X[-1][4] ^ mod_sum(F0(X[-1][3]), SK[4 * i + 1]))
        X_tmp.append(X[-1][5])
        X_tmp.append(mod_sub(X[-1][6], (F1(X[-1][5]) ^ SK[4 * i + 2])))
        X_tmp.append(X[-1][7])
        X_tmp.append(X[-1][0] ^ mod_sum(F0(X[-1][7]), SK[4 * i + 3]))
        X.append(X_tmp)

    P = []
    P.append(mod_sub(X[32][0], WK[0]))
    P.append(X[32][1])
    P.append(X[32][2] ^ WK[1])
    P.append(X[32][3])
    P.append(mod_sub(X[32][4], WK[2]))
    P.append(X[32][5])
    P.append(X[32][6] ^ WK[3])
    P.append(X[32][7])

    return P

K_str = "abcdefghijklmnop"
print(K_str)
K = [ord(c) for c in K_str]

P_str = "passw0rd"
print(P_str)
P = [ord(c) for c in P_str]

C = hight_enc(P, K)
C_str = [chr(c) for c in C]
print("".join(C_str), "-->", C_str)

P_dec = hight_dec(C, K)
P_dec_str = "".join(chr(c) for c in P_dec)
print(P_dec_str)
