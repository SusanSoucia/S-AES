"""
S-AES核心算法实现
实现简化AES算法的基本加解密、密钥扩展、双重加密、三重加密等功能
"""

# S盒与逆S盒定义
S_BOX = {
    0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
    0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
    0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
    0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
}

INV_S_BOX = {v: k for k, v in S_BOX.items()}


def gf_mul(a, b):
    """GF(2^4)有限域乘法，模多项式x⁴+x+1"""
    if a == 0 or b == 0:
        return 0x0

    result = 0x0
    b_poly = b
    for _ in range(4):
        if b_poly & 0x1:
            result ^= a
        carry = a & 0x8
        a = (a << 1) & 0xF
        if carry:
            a ^= 0x3  # x⁴ + x + 1 = 10011，取低4位为0011即0x3
        b_poly >>= 1
    return result


def int_to_state(n):
    """将16位整数转换为2x2状态矩阵"""
    return [
        [(n >> 12) & 0xF, (n >> 4) & 0xF],
        [(n >> 8) & 0xF, n & 0xF]
    ]


def state_to_int(state):
    """将2x2状态矩阵转换为16位整数"""
    return (state[0][0] << 12) | (state[1][0] << 8) | (state[0][1] << 4) | state[1][1]


def add_round_key(state, round_key):
    """密钥加操作"""
    key_state = int_to_state(round_key)
    return [[state[i][j] ^ key_state[i][j] for j in range(2)] for i in range(2)]


def sub_nibbles(state, inv=False):
    """半字节替换"""
    box = INV_S_BOX if inv else S_BOX
    return [[box[state[i][j]] for j in range(2)] for i in range(2)]


def shift_rows(state, inv=False):
    """行移位"""
    # 行移位是自逆的，加密和解密操作相同
    return [
        [state[0][0], state[0][1]],
        [state[1][1], state[1][0]]
    ]


def mix_columns(state, inv=False):
    """列混淆"""
    if inv:
        # 逆列混淆矩阵: [[9, 2], [2, 9]]
        return [
            [
                gf_mul(0x9, state[0][0]) ^ gf_mul(0x2, state[1][0]),
                gf_mul(0x9, state[0][1]) ^ gf_mul(0x2, state[1][1])
            ],
            [
                gf_mul(0x2, state[0][0]) ^ gf_mul(0x9, state[1][0]),
                gf_mul(0x2, state[0][1]) ^ gf_mul(0x9, state[1][1])
            ]
        ]
    else:
        # 列混淆矩阵: [[1, 4], [4, 1]]
        return [
            [
                state[0][0] ^ gf_mul(0x4, state[1][0]),
                state[0][1] ^ gf_mul(0x4, state[1][1])
            ],
            [
                gf_mul(0x4, state[0][0]) ^ state[1][0],
                gf_mul(0x4, state[0][1]) ^ state[1][1]
            ]
        ]


def g_function(w, rcon):
    """密钥扩展的g函数"""
    # 半字节旋转
    rot = ((w & 0x0F) << 4) | ((w & 0xF0) >> 4)
    # 半字节替换
    sub = (S_BOX[(rot >> 4) & 0xF] << 4) | S_BOX[rot & 0xF]
    # 轮常数异或
    return (sub & 0x0F) | ((sub & 0xF0) ^ rcon)


def key_expansion(initial_key):
    """密钥扩展，生成轮密钥"""
    w0 = (initial_key >> 8) & 0xFF
    w1 = initial_key & 0xFF
    w2 = w0 ^ g_function(w1, 0x80)  # RCON(1) = 0x80
    w3 = w2 ^ w1
    w4 = w2 ^ g_function(w3, 0x30)  # RCON(2) = 0x30
    w5 = w4 ^ w3
    return [
        (w0 << 8) | w1,  # K0
        (w2 << 8) | w3,  # K1
        (w4 << 8) | w5  # K2
    ]


def encrypt(plaintext, key):
    """S-AES加密单个16位分组"""
    if not (0 <= plaintext <= 0xFFFF and 0 <= key <= 0xFFFF):
        raise ValueError("明文和密钥必须是16位整数")

    K0, K1, K2 = key_expansion(key)
    state = int_to_state(plaintext)

    # 第0轮：密钥加
    state = add_round_key(state, K0)

    # 第1轮
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, K1)

    # 第2轮
    state = sub_nibbles(state)
    state = shift_rows(state)
    state = add_round_key(state, K2)

    return state_to_int(state)


def decrypt(ciphertext, key):
    """S-AES解密单个16位分组"""
    if not (0 <= ciphertext <= 0xFFFF and 0 <= key <= 0xFFFF):
        raise ValueError("密文和密钥必须是16位整数")

    K0, K1, K2 = key_expansion(key)
    state = int_to_state(ciphertext)

    # 第0轮（对应加密第2轮）
    state = add_round_key(state, K2)
    state = shift_rows(state, inv=True)
    state = sub_nibbles(state, inv=True)

    # 第1轮（对应加密第1轮）
    state = add_round_key(state, K1)
    state = mix_columns(state, inv=True)
    state = shift_rows(state, inv=True)
    state = sub_nibbles(state, inv=True)

    # 第2轮（对应加密第0轮）
    state = add_round_key(state, K0)

    return state_to_int(state)


def double_encrypt(plaintext, key):
    """双重加密，32位密钥(key = K1 << 16 | K2)"""
    if not (0 <= plaintext <= 0xFFFF and 0 <= key <= 0xFFFFFFFF):
        raise ValueError("明文必须是16位整数，密钥必须是32位整数")

    k1 = (key >> 16) & 0xFFFF  # 前16位作为K1
    k2 = key & 0xFFFF  # 后16位作为K2
    return encrypt(encrypt(plaintext, k1), k2)


def double_decrypt(ciphertext, key):
    """双重解密"""
    if not (0 <= ciphertext <= 0xFFFF and 0 <= key <= 0xFFFFFFFF):
        raise ValueError("密文必须是16位整数，密钥必须是32位整数")

    k1 = (key >> 16) & 0xFFFF
    k2 = key & 0xFFFF
    return decrypt(decrypt(ciphertext, k2), k1)


def triple_encrypt(plaintext, key, mode=1):
    """三重加密
    mode=1: 32位密钥(K1+K2)，模式为K1-K2-K1
    mode=2: 48位密钥(K1+K2+K3)，模式为K1-K2-K3
    """
    if mode == 1:
        if not (0 <= plaintext <= 0xFFFF and 0 <= key <= 0xFFFFFFFF):
            raise ValueError("明文必须是16位整数，密钥必须是32位整数")
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        return encrypt(decrypt(encrypt(plaintext, k1), k2), k1)
    else:  # mode=2
        if not (0 <= plaintext <= 0xFFFF and 0 <= key <= 0xFFFFFFFFFFFF):
            raise ValueError("明文必须是16位整数，密钥必须是48位整数")
        k1 = (key >> 32) & 0xFFFF
        k2 = (key >> 16) & 0xFFFF
        k3 = key & 0xFFFF
        return encrypt(decrypt(encrypt(plaintext, k1), k2), k3)


def triple_decrypt(ciphertext, key, mode=1):
    """三重解密"""
    if mode == 1:
        if not (0 <= ciphertext <= 0xFFFF and 0 <= key <= 0xFFFFFFFF):
            raise ValueError("密文必须是16位整数，密钥必须是32位整数")
        k1 = (key >> 16) & 0xFFFF
        k2 = key & 0xFFFF
        return decrypt(encrypt(decrypt(ciphertext, k1), k2), k1)
    else:  # mode=2
        if not (0 <= ciphertext <= 0xFFFF and 0 <= key <= 0xFFFFFFFFFFFF):
            raise ValueError("密文必须是16位整数，密钥必须是48位整数")
        k1 = (key >> 32) & 0xFFFF
        k2 = (key >> 16) & 0xFFFF
        k3 = key & 0xFFFF
        return decrypt(encrypt(decrypt(ciphertext, k3), k2), k1)


def meet_in_the_middle(plaintext, ciphertext):
    """中间相遇攻击，寻找双重加密的32位密钥"""
    if not (0 <= plaintext <= 0xFFFF and 0 <= ciphertext <= 0xFFFF):
        raise ValueError("明文和密文必须是16位整数")

    # 存储所有可能的K1及其对应的中间值
    forward = {}
    for k1 in range(0x10000):
        intermediate = encrypt(plaintext, k1)
        forward[intermediate] = k1

    # 寻找匹配的K2
    for k2 in range(0x10000):
        intermediate = decrypt(ciphertext, k2)
        if intermediate in forward:
            # 找到可能的密钥对
            k1 = forward[intermediate]
            return (k1 << 16) | k2  # 组合成32位密钥

    return None  # 未找到密钥

if __name__ == "__main__":
    # 测试输入转换
    test = 0xa749
    state = int_to_state(test)
    print("state：",state)

    # 测试密钥加
    res = add_round_key(state,0x2d55)
    print("密钥加的结果:",res)

    # 测试半字节代替
    res1 = sub_nibbles(res,False)
    print("测试代替函数：",res1)

    # 测试行移位
    res2 = shift_rows(res1)
    print("测试行移位：",res2)

    # 测试列混淆
    res3 = mix_columns(res2,False)
    print("测试列混淆：",res3)