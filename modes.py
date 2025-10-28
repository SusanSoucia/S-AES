"""
加密模式实现
实现CBC等分组密码工作模式
"""
import random
from s_aes_core import encrypt, decrypt


def cbc_encrypt(plaintext_bytes, key, iv=None):
    """
    CBC模式加密
    plaintext_bytes: 明文字节串
    key: 16位密钥
    iv: 16位初始向量，None则自动生成
    返回: (密文字节串, iv)
    """
    if iv is None:
        iv = random.getrandbits(16)  # 生成随机IV

    # 填充明文，使其长度为2的倍数
    pad_length = (2 - (len(plaintext_bytes) % 2)) % 2
    plaintext_bytes += bytes([pad_length]) * pad_length

    ciphertext_bytes = b""
    prev_block = iv

    # 按2字节一组处理
    for i in range(0, len(plaintext_bytes), 2):
        # 提取2字节明文并转换为16位整数
        block = int.from_bytes(plaintext_bytes[i:i + 2], byteorder='big')
        # 与前一个密文块异或
        block ^= prev_block
        # 加密
        cipher_block = encrypt(block, key)
        # 保存密文块
        ciphertext_bytes += cipher_block.to_bytes(2, byteorder='big')
        # 更新前一个密文块
        prev_block = cipher_block

    return (ciphertext_bytes, iv)


def cbc_decrypt(ciphertext_bytes, key, iv):
    """
    CBC模式解密
    ciphertext_bytes: 密文字节串
    key: 16位密钥
    iv: 16位初始向量
    返回: 明文字节串（去除填充）
    """
    if len(ciphertext_bytes) % 2 != 0:
        raise ValueError("密文长度必须是2的倍数")

    plaintext_bytes = b""
    prev_block = iv

    # 按2字节一组处理
    for i in range(0, len(ciphertext_bytes), 2):
        # 提取2字节密文并转换为16位整数
        cipher_block = int.from_bytes(ciphertext_bytes[i:i + 2], byteorder='big')
        # 解密
        block = decrypt(cipher_block, key)
        # 与前一个密文块异或
        block ^= prev_block
        # 保存明文块
        plaintext_bytes += block.to_bytes(2, byteorder='big')
        # 更新前一个密文块
        prev_block = cipher_block

    # 去除填充
    pad_length = plaintext_bytes[-1] if plaintext_bytes else 0
    if pad_length < 1 or pad_length > 2:
        return plaintext_bytes  # 填充异常，返回原始数据
    return plaintext_bytes[:-pad_length]