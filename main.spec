# -*- mode: python ; coding: utf-8 -*-
DIR="C:\\Program Files\\test\\"

block_cipher = None


a = Analysis(['main.py'],
             pathex=['C:\\Users\\LG\\PycharmProjects\\pythonProject'],
             binaries=[('FortiSSLVPNclient.exe','./resource'),('libcrypto-1_1.dll','./resource'),('libssl-1_1.dll','./resource'),('mfc140.dll','./resource'),('msvcp140.dll','./resource'),('vcruntime140.dll','./resource')],
             datas=[('unnamed.png','./resource'),('screen1.ui','./resource'),('screen2.ui','./resource'),('screen3.ui','./resource')],
             hiddenimports=['sys','os','subprocess','re','pyotp','base64','hashlib','sqlite3','platform','psutil','Cryptodome.Cipher.AES','PyQt5.QtWidgets','PyQt5.QtWidgets','PyQt5.uic','PyQt5.QtCore','PyQt5.QtWidgets.QDialog','PyQt5.QtWidgets.QApplication'],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,  
          [],
          name='VPN_Exchanger',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=False,
          disable_windowed_traceback=False,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None,
           icon='./icon.ico')
