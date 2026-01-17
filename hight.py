BITS = 7


def mod_sum(a, b):
    return (a + b) % (2**BITS)


def mod_sub(a, b):
    return (a - b) % (2**BITS)


def GenerateRoundKeys(Key):
    whiteningKey = []
    for i in range(4):
        whiteningKey.append(Key[i + 12])
    for i in range(4, 8):
        whiteningKey.append(Key[i - 4])

    subKey = []
    s = [0, 1, 0, 1, 1, 0, 1]
    delta = []
    delta.append("".join(str(s[i]) for i in range(6, -1, -1)))

    for i in range(1, 128):
        s.append(s[i + 2 - 1] ^ s[i - 1 - 1])
        delta.append("".join(str(s[j]) for j in range(i + 6, i - 1, -1)))

    for i in range(8):
        for j in range(8):
            subKey.append(mod_sum(Key[(j - i) % 8], int(delta[16 * i + j], 2)))
        for j in range(8):
            subKey.append(
                mod_sum(Key[((j - i) % 8) + 8], int(delta[16 * i + j + 8], 2))
            )

    return whiteningKey, subKey


def rol(val, i_bits, max_bits=BITS):
    return ((val << i_bits) & (2**max_bits - 1)) | (val >> (max_bits - i_bits))


def F0(x):
    return rol(x, 1) ^ rol(x, 2) ^ rol(x, 7)


def F1(x):
    return rol(x, 3) ^ rol(x, 4) ^ rol(x, 6)


def EncryptBlock(P, K):
    # P - plaintext block
    # K - key
    WK, SK = GenerateRoundKeys(K)
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


def DecryptBlock(C, K):
    # C - ciphertext block
    # K - key
    WK, SK = GenerateRoundKeys(K)
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


def EncryptData(Data, Key):
    EncryptedData = []
    for i in range(0, len(Data), 8):
        Block = Data[i : i + 8]
        if len(Block) < 8:
            Block += [0] * (8 - len(Block))
        EncryptedBlock = EncryptBlock(Block, Key)
        EncryptedData.extend(EncryptedBlock)
    return EncryptedData


def DecryptData(Data, Key):
    DecryptedData = []
    for i in range(0, len(Data), 8):
        Block = Data[i : i + 8]
        if len(Block) < 8:
            raise ValueError("Encrypted data length is wrong")
        DecryptedBlock = DecryptBlock(Block, Key)
        DecryptedData.extend(DecryptedBlock)
    return DecryptedData

K_str = "abcdefghijklmnop"
print(K_str)
K = [ord(c) for c in K_str]

Data_str = "Perspiciatis omnis laborum harum sapiente voluptatem sit vel. Corrupti ea aliquid cum et sint quia. Quia id ex ab laborum qui enim nesciunt quos. Quia deleniti facere culpa et qui impedit accusantium minima."
print(Data_str)
Data = [ord(c) for c in Data_str]

EncryptedData = EncryptData(Data, K)
EncryptedData_str = [chr(c) for c in EncryptedData]
print("".join(EncryptedData_str))
print("-->")
print(EncryptedData_str)

DecryptedData = DecryptData(EncryptedData, K)
DecryptedData_str = "".join(chr(c) for c in DecryptedData)
print(DecryptedData_str)

TestEncryptedData = EncryptedData + [0, 0, 0]
try:
    DecryptData(TestEncryptedData, K)
except ValueError as e:
    print(f"Caught expected exception: {e}")
