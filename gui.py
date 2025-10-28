"""
S-AES加解密程序图形界面
使用PyQt5实现用户交互界面
"""
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget,
                             QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                             QPushButton, QTextEdit, QGroupBox, QRadioButton,
                             QComboBox, QMessageBox, QSplitter)
from PyQt5.QtCore import Qt
from s_aes_core import (encrypt, decrypt, double_encrypt, double_decrypt,
                        triple_encrypt, triple_decrypt, meet_in_the_middle)
from modes import cbc_encrypt, cbc_decrypt
from utils import str_to_hex_blocks, hex_blocks_to_str, hex_to_int, int_to_hex


class SAESGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle("S-AES加解密工具")
        self.setGeometry(100, 100, 800, 600)

        # 创建主部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 创建标签页控件
        self.tabs = QTabWidget()

        # 添加各个功能标签页
        self.tabs.addTab(self.create_basic_tab(), "基本加解密")
        self.tabs.addTab(self.create_string_tab(), "字符串加解密")
        self.tabs.addTab(self.create_multi_tab(), "多重加密")
        self.tabs.addTab(self.create_attack_tab(), "中间相遇攻击")
        self.tabs.addTab(self.create_mode_tab(), "工作模式(CBC)")

        main_layout.addWidget(self.tabs)

        # 显示窗口
        self.show()

    def create_basic_tab(self):
        """创建基本加解密标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()

        # 明文/密文输入
        plaintext_layout = QHBoxLayout()
        plaintext_layout.addWidget(QLabel("明文/密文 (16位十六进制):"))
        self.basic_data_input = QLineEdit()
        self.basic_data_input.setPlaceholderText("例如: 1234 或 0x1234")
        plaintext_layout.addWidget(self.basic_data_input)
        input_layout.addLayout(plaintext_layout)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("密钥 (16位十六进制):"))
        self.basic_key_input = QLineEdit()
        self.basic_key_input.setPlaceholderText("例如: 2D55 或 0x2D55")
        key_layout.addWidget(self.basic_key_input)
        input_layout.addLayout(key_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.encrypt_btn = QPushButton("加密")
        self.encrypt_btn.clicked.connect(self.basic_encrypt)
        self.decrypt_btn = QPushButton("解密")
        self.decrypt_btn.clicked.connect(self.basic_decrypt)
        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.addWidget(self.decrypt_btn)
        layout.addLayout(btn_layout)

        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        self.basic_result = QTextEdit()
        self.basic_result.setReadOnly(True)
        output_layout.addWidget(self.basic_result)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch(1)
        return tab

    def create_string_tab(self):
        """创建字符串加解密标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()

        # 字符串输入
        str_layout = QHBoxLayout()
        str_layout.addWidget(QLabel("字符串 (ASCII):"))
        self.string_input = QLineEdit()
        str_layout.addWidget(self.string_input)
        input_layout.addLayout(str_layout)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("密钥 (16位十六进制):"))
        self.string_key_input = QLineEdit()
        self.string_key_input.setPlaceholderText("例如: 2D55 或 0x2D55")
        key_layout.addWidget(self.string_key_input)
        input_layout.addLayout(key_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.str_encrypt_btn = QPushButton("加密")
        self.str_encrypt_btn.clicked.connect(self.string_encrypt)
        self.str_decrypt_btn = QPushButton("解密")
        self.str_decrypt_btn.clicked.connect(self.string_decrypt)
        btn_layout.addWidget(self.str_encrypt_btn)
        btn_layout.addWidget(self.str_decrypt_btn)
        layout.addLayout(btn_layout)

        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        self.string_result = QTextEdit()
        self.string_result.setReadOnly(True)
        output_layout.addWidget(self.string_result)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch(1)
        return tab

    def create_multi_tab(self):
        """创建多重加密标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 加密类型选择
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("加密类型:"))
        self.multi_type = QComboBox()
        self.multi_type.addItems(["双重加密", "三重加密(32位密钥)", "三重加密(48位密钥)"])
        type_layout.addWidget(self.multi_type)
        layout.addLayout(type_layout)

        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()

        # 明文/密文输入
        data_layout = QHBoxLayout()
        data_layout.addWidget(QLabel("明文/密文 (16位十六进制):"))
        self.multi_data_input = QLineEdit()
        self.multi_data_input.setPlaceholderText("例如: 1234 或 0x1234")
        data_layout.addWidget(self.multi_data_input)
        input_layout.addLayout(data_layout)

        # 密钥输入
        key_layout = QHBoxLayout()
        self.key_label = QLabel("密钥 (32位十六进制):")
        key_layout.addWidget(self.key_label)
        self.multi_key_input = QLineEdit()
        self.multi_key_input.setPlaceholderText("例如: 12345678 或 0x12345678")
        key_layout.addWidget(self.multi_key_input)
        input_layout.addLayout(key_layout)

        # 三重加密模式选择
        self.triple_mode_layout = QHBoxLayout()
        self.triple_mode_label = QLabel("三重加密模式:")
        self.triple_mode = QComboBox()
        self.triple_mode.addItems(["K1-K2-K1", "K1-K2-K3"])
        self.triple_mode_layout.addWidget(self.triple_mode_label)
        self.triple_mode_layout.addWidget(self.triple_mode)
        input_layout.addLayout(self.triple_mode_layout)

        # 初始隐藏三重加密模式选择
        self.triple_mode_label.setVisible(False)
        self.triple_mode.setVisible(False)

        # 当选择变化时更新界面
        self.multi_type.currentIndexChanged.connect(self.update_multi_tab)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.multi_encrypt_btn = QPushButton("加密")
        self.multi_encrypt_btn.clicked.connect(self.multi_encrypt)
        self.multi_decrypt_btn = QPushButton("解密")
        self.multi_decrypt_btn.clicked.connect(self.multi_decrypt)
        btn_layout.addWidget(self.multi_encrypt_btn)
        btn_layout.addWidget(self.multi_decrypt_btn)
        layout.addLayout(btn_layout)

        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        self.multi_result = QTextEdit()
        self.multi_result.setReadOnly(True)
        output_layout.addWidget(self.multi_result)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch(1)
        return tab

    def create_attack_tab(self):
        """创建中间相遇攻击标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 输入区域
        input_group = QGroupBox("明密文对")
        input_layout = QVBoxLayout()

        # 明文输入
        plain_layout = QHBoxLayout()
        plain_layout.addWidget(QLabel("明文 (16位十六进制):"))
        self.attack_plain_input = QLineEdit()
        self.attack_plain_input.setPlaceholderText("例如: 1234 或 0x1234")
        plain_layout.addWidget(self.attack_plain_input)
        input_layout.addLayout(plain_layout)

        # 密文输入
        cipher_layout = QHBoxLayout()
        cipher_layout.addWidget(QLabel("密文 (16位十六进制):"))
        self.attack_cipher_input = QLineEdit()
        self.attack_cipher_input.setPlaceholderText("例如: 5678 或 0x5678")
        cipher_layout.addWidget(self.attack_cipher_input)
        input_layout.addLayout(cipher_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.attack_btn = QPushButton("执行中间相遇攻击")
        self.attack_btn.clicked.connect(self.perform_attack)
        btn_layout.addWidget(self.attack_btn)
        layout.addLayout(btn_layout)

        # 输出区域
        output_group = QGroupBox("攻击结果")
        output_layout = QVBoxLayout()
        self.attack_result = QTextEdit()
        self.attack_result.setReadOnly(True)
        output_layout.addWidget(self.attack_result)
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch(1)
        return tab

    def create_mode_tab(self):
        """创建工作模式标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()

        # 明文/密文输入
        text_layout = QHBoxLayout()
        text_layout.addWidget(QLabel("文本 (ASCII):"))
        self.mode_text_input = QLineEdit()
        text_layout.addWidget(self.mode_text_input)
        input_layout.addLayout(text_layout)

        # 密钥输入
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("密钥 (16位十六进制):"))
        self.mode_key_input = QLineEdit()
        self.mode_key_input.setPlaceholderText("例如: 2D55 或 0x2D55")
        key_layout.addWidget(self.mode_key_input)
        input_layout.addLayout(key_layout)

        # IV输入
        iv_layout = QHBoxLayout()
        iv_layout.addWidget(QLabel("初始向量IV (16位十六进制，留空自动生成):"))
        self.mode_iv_input = QLineEdit()
        self.mode_iv_input.setPlaceholderText("例如: 3C7A 或 0x3C7A")
        iv_layout.addWidget(self.mode_iv_input)
        input_layout.addLayout(iv_layout)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮区域
        btn_layout = QHBoxLayout()
        self.mode_encrypt_btn = QPushButton("CBC加密")
        self.mode_encrypt_btn.clicked.connect(self.mode_encrypt)
        self.mode_decrypt_btn = QPushButton("CBC解密")
        self.mode_decrypt_btn.clicked.connect(self.mode_decrypt)
        btn_layout.addWidget(self.mode_encrypt_btn)
        btn_layout.addWidget(self.mode_decrypt_btn)
        layout.addLayout(btn_layout)

        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()

        # IV输出
        iv_output_layout = QHBoxLayout()
        iv_output_layout.addWidget(QLabel("使用的IV:"))
        self.mode_iv_output = QLineEdit()
        self.mode_iv_output.setReadOnly(True)
        iv_output_layout.addWidget(self.mode_iv_output)
        output_layout.addLayout(iv_output_layout)

        # 结果输出
        self.mode_result = QTextEdit()
        self.mode_result.setReadOnly(True)
        output_layout.addWidget(self.mode_result)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch(1)
        return tab

    def update_multi_tab(self):
        """更新多重加密标签页的显示"""
        index = self.multi_type.currentIndex()
        if index == 0:  # 双重加密
            self.key_label.setText("密钥 (32位十六进制):")
            self.multi_key_input.setPlaceholderText("例如: 12345678 或 0x12345678")
            self.triple_mode_label.setVisible(False)
            self.triple_mode.setVisible(False)
        elif index == 1:  # 三重加密(32位)
            self.key_label.setText("密钥 (32位十六进制):")
            self.multi_key_input.setPlaceholderText("例如: 12345678 或 0x12345678")
            self.triple_mode_label.setVisible(True)
            self.triple_mode.setVisible(True)
            self.triple_mode.setCurrentIndex(0)
            self.triple_mode.setEnabled(False)  # 32位密钥只能用K1-K2-K1模式
        else:  # 三重加密(48位)
            self.key_label.setText("密钥 (48位十六进制):")
            self.multi_key_input.setPlaceholderText("例如: 123456789ABC 或 0x123456789ABC")
            self.triple_mode_label.setVisible(True)
            self.triple_mode.setVisible(True)
            self.triple_mode.setCurrentIndex(1)
            self.triple_mode.setEnabled(True)

    def basic_encrypt(self):
        """基本加密功能"""
        try:
            # 获取输入
            data_hex = self.basic_data_input.text().strip()
            key_hex = self.basic_key_input.text().strip()

            # 转换为整数
            data = hex_to_int(data_hex, 16)
            key = hex_to_int(key_hex, 16)

            # 执行加密
            result = encrypt(data, key)

            # 显示结果
            self.basic_result.setText(f"加密结果: {int_to_hex(result, 16)}")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {str(e)}")

    def basic_decrypt(self):
        """基本解密功能"""
        try:
            # 获取输入
            data_hex = self.basic_data_input.text().strip()
            key_hex = self.basic_key_input.text().strip()

            # 转换为整数
            data = hex_to_int(data_hex, 16)
            key = hex_to_int(key_hex, 16)

            # 执行解密
            result = decrypt(data, key)

            # 显示结果
            self.basic_result.setText(f"解密结果: {int_to_hex(result, 16)}")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {str(e)}")

    def string_encrypt(self):
        """字符串加密功能"""
        try:
            # 获取输入
            text = self.string_input.text().strip()
            key_hex = self.string_key_input.text().strip()

            if not text:
                QMessageBox.warning(self, "警告", "请输入要加密的字符串")
                return

            # 转换密钥
            key = hex_to_int(key_hex, 16)

            # 将字符串转换为16位块
            blocks = str_to_hex_blocks(text)

            # 逐个块加密
            encrypted_blocks = [encrypt(block, key) for block in blocks]

            # 转换为字符串
            encrypted_str = hex_blocks_to_str(encrypted_blocks)

            # 显示结果
            block_hex = [int_to_hex(b) for b in encrypted_blocks]
            self.string_result.setText(
                f"原始字符串: {text}\n"
                f"加密后块: {block_hex}\n"
                f"加密后字符串: {encrypted_str}"
            )

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {str(e)}")

    def string_decrypt(self):
        """字符串解密功能"""
        try:
            # 获取输入
            text = self.string_input.text().strip()
            key_hex = self.string_key_input.text().strip()

            if not text:
                QMessageBox.warning(self, "警告", "请输入要解密的字符串")
                return

            # 转换密钥
            key = hex_to_int(key_hex, 16)

            # 将字符串转换为16位块
            blocks = str_to_hex_blocks(text)

            # 逐个块解密
            decrypted_blocks = [decrypt(block, key) for block in blocks]

            # 转换为字符串
            decrypted_str = hex_blocks_to_str(decrypted_blocks)

            # 显示结果
            block_hex = [int_to_hex(b) for b in decrypted_blocks]
            self.string_result.setText(
                f"加密字符串: {text}\n"
                f"解密后块: {block_hex}\n"
                f"解密后字符串: {decrypted_str}"
            )

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {str(e)}")

    def multi_encrypt(self):
        """多重加密功能"""
        try:
            # 获取输入
            data_hex = self.multi_data_input.text().strip()
            key_hex = self.multi_key_input.text().strip()
            type_index = self.multi_type.currentIndex()

            # 转换为整数
            data = hex_to_int(data_hex, 16)

            # 根据加密类型处理
            if type_index == 0:  # 双重加密
                key = hex_to_int(key_hex, 32)
                result = double_encrypt(data, key)
                msg = f"双重加密结果: {int_to_hex(result, 16)}"

            elif type_index == 1:  # 三重加密(32位)
                key = hex_to_int(key_hex, 32)
                result = triple_encrypt(data, key, mode=1)
                msg = f"三重加密(K1-K2-K1)结果: {int_to_hex(result, 16)}"

            else:  # 三重加密(48位)
                key = hex_to_int(key_hex, 48)
                mode = 1 if self.triple_mode.currentIndex() == 0 else 2
                result = triple_encrypt(data, key, mode=mode)
                msg = f"三重加密({self.triple_mode.currentText()})结果: {int_to_hex(result, 16)}"

            # 显示结果
            self.multi_result.setText(msg)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {str(e)}")

    def multi_decrypt(self):
        """多重解密功能"""
        try:
            # 获取输入
            data_hex = self.multi_data_input.text().strip()
            key_hex = self.multi_key_input.text().strip()
            type_index = self.multi_type.currentIndex()

            # 转换为整数
            data = hex_to_int(data_hex, 16)

            # 根据加密类型处理
            if type_index == 0:  # 双重解密
                key = hex_to_int(key_hex, 32)
                result = double_decrypt(data, key)
                msg = f"双重解密结果: {int_to_hex(result, 16)}"

            elif type_index == 1:  # 三重解密(32位)
                key = hex_to_int(key_hex, 32)
                result = triple_decrypt(data, key, mode=1)
                msg = f"三重解密(K1-K2-K1)结果: {int_to_hex(result, 16)}"

            else:  # 三重解密(48位)
                key = hex_to_int(key_hex, 48)
                mode = 1 if self.triple_mode.currentIndex() == 0 else 2
                result = triple_decrypt(data, key, mode=mode)
                msg = f"三重解密({self.triple_mode.currentText()})结果: {int_to_hex(result, 16)}"

            # 显示结果
            self.multi_result.setText(msg)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {str(e)}")

    def perform_attack(self):
        """执行中间相遇攻击"""
        try:
            # 获取输入
            plain_hex = self.attack_plain_input.text().strip()
            cipher_hex = self.attack_cipher_input.text().strip()

            # 转换为整数
            plaintext = hex_to_int(plain_hex, 16)
            ciphertext = hex_to_int(cipher_hex, 16)

            # 显示攻击开始信息
            self.attack_result.setText("正在执行中间相遇攻击，请稍候...\n"
                                       "这可能需要几秒钟时间...")
            # 强制刷新界面
            QApplication.processEvents()

            # 执行攻击
            key = meet_in_the_middle(plaintext, ciphertext)

            # 显示结果
            if key is not None:
                k1 = (key >> 16) & 0xFFFF
                k2 = key & 0xFFFF
                self.attack_result.setText(
                    f"攻击成功！找到密钥对:\n"
                    f"32位密钥: {int_to_hex(key, 32)}\n"
                    f"K1: {int_to_hex(k1, 16)}\n"
                    f"K2: {int_to_hex(k2, 16)}"
                )
            else:
                self.attack_result.setText("攻击失败，未找到匹配的密钥对")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"攻击失败: {str(e)}")

    def mode_encrypt(self):
        """CBC模式加密"""
        try:
            # 获取输入
            text = self.mode_text_input.text().strip()
            key_hex = self.mode_key_input.text().strip()
            iv_hex = self.mode_iv_input.text().strip()

            if not text:
                QMessageBox.warning(self, "警告", "请输入要加密的文本")
                return

            # 转换密钥
            key = hex_to_int(key_hex, 16)

            # 处理IV
            iv = None
            if iv_hex:
                iv = hex_to_int(iv_hex, 16)

            # 执行CBC加密
            cipher_bytes, used_iv = cbc_encrypt(text.encode('ascii'), key, iv)

            # 显示结果
            self.mode_iv_output.setText(int_to_hex(used_iv, 16))
            self.mode_result.setText(
                f"原始文本: {text}\n"
                f"加密后字节: {cipher_bytes.hex()}\n"
                f"加密后文本: {cipher_bytes.decode('latin-1')}"
            )

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {str(e)}")

    def mode_decrypt(self):
        """CBC模式解密"""
        try:
            # 获取输入
            text = self.mode_text_input.text().strip()
            key_hex = self.mode_key_input.text().strip()
            iv_hex = self.mode_iv_input.text().strip()

            if not text:
                QMessageBox.warning(self, "警告", "请输入要解密的文本")
                return

            if not iv_hex:
                QMessageBox.warning(self, "警告", "请输入初始向量IV")
                return

            # 转换密钥和IV
            key = hex_to_int(key_hex, 16)
            iv = hex_to_int(iv_hex, 16)

            # 将输入文本转换为字节：优先十六进制，失败则按ASCII
            try:
                cipher_bytes = bytes.fromhex(text)
            except ValueError:
                cipher_bytes = text.encode('latin-1')

            # 执行CBC解密
            plain_bytes = cbc_decrypt(cipher_bytes, key, iv)

            # 显示结果
            self.mode_iv_output.setText(int_to_hex(iv, 16))
            self.mode_result.setText(
                f"加密文本: {text}\n"
                f"解密后字节: {plain_bytes.hex()}\n"
                f"解密后文本: {plain_bytes.decode('latin-1')}"
            )

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {str(e)}")