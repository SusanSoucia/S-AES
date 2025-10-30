"""
工具函数
提供数据格式转换等辅助功能
"""


def str_to_hex_blocks(text):
    """将字符串转换为16位十六进制块的列表"""
    blocks = []
    # 将字符串转换为字节
    bytes_data = text.encode('ascii')

    # 按2字节一组处理
    for i in range(0, len(bytes_data), 2):
        # 提取2字节
        block_bytes = bytes_data[i:i + 2]
        # 如果不足2字节，补0
        if len(block_bytes) < 2:
            block_bytes += b'\x00' * (2 - len(block_bytes))
        # 转换为16位整数
        block = int.from_bytes(block_bytes, byteorder='big')
        blocks.append(block)

    return blocks


def hex_blocks_to_str(blocks):
    """将16位十六进制块的列表转换为字符串"""
    bytes_data = b""
    for block in blocks:
        # 转换为2字节
        block_bytes = block.to_bytes(2, byteorder='big')
        bytes_data += block_bytes

    # 尝试解码为ASCII字符串，忽略无法解码的字节
    try:
        return bytes_data.rstrip(b'\x00').decode('latin-1',errors='replace')
    except UnicodeDecodeError:
        return str(bytes_data)


def hex_to_int(hex_str, bits=16):
    """将十六进制字符串转换为指定位数的整数"""
    try:
        # 移除可能的0x前缀
        if hex_str.startswith('0x'):
            hex_str = hex_str[2:]
        # 转换为整数
        value = int(hex_str, 16)
        # 检查是否在指定位数范围内
        if 0 <= value <= (1 << bits) - 1:
            return value
        else:
            raise ValueError(f"值超出{bits}位范围")
    except ValueError:
        raise ValueError(f"无效的十六进制字符串: {hex_str}")


def int_to_hex(value, bits=16):
    """将整数转换为指定位数的十六进制字符串"""
    if not (0 <= value <= (1 << bits) - 1):
        raise ValueError(f"值超出{bits}位范围")
    # 计算需要的十六进制位数
    hex_digits = (bits + 3) // 4
    return f"0x{value:0{hex_digits}X}"