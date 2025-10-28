"""
S-AES加解密程序主入口
"""
import sys
from PyQt5.QtWidgets import QApplication
from gui import SAESGUI

def main():
    """主函数"""
    app = QApplication(sys.argv)
    window = SAESGUI()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()