import sys,os,subprocess,re, pyotp ,base64 ,hashlib, sqlite3,platform,signal,psutil
from Cryptodome.Cipher import AES
from PyQt5.QtWidgets import *
from PyQt5 import QtWidgets,uic,QtCore
from PyQt5.QtGui import *
from PyQt5.QtWidgets import QDialog, QApplication

try:
    work_dir = sys._MEIPASS
    os.chdir(sys._MEIPASS)
    print("dir2: " + sys._MEIPASS)
except:
    work_dir = os.getcwd()
    os.chdir(os.getcwd())
    print("dir: " + work_dir)
form_class1 = uic.loadUiType(work_dir + "/resource/screen1.ui")[0]
form_class2 = uic.loadUiType(work_dir + "/resource/screen2.ui")[0]
form_class3 = uic.loadUiType(work_dir + "/resource/screen3.ui")[0]
home_dir=os.path.expanduser('~')

br_text="""[%s VPN 등록 메뉴입니다.]
첫번째 칸에 VPN ID를 입력합니다.

두번째 칸에 VPN 패스워드를 입력합니다.(순수 패스워드만 입력)

세번째 칸에 Radius 시크릿 정보를 입력합니다.(보안팀에게 문의 @draven)

네번째 칸에 영소문자+대문자+숫자+특수문자 조합의 키를 입력합니다.
(최소 8자리 이상, 이 프로그램에서 사용할 패스워드입니다."""
int_text,ext_text,port_text=br_text % "업무망",br_text % "인터넷망",br_text % "(포트)업무망"
int_table,ext_table,port_table="int_info","ext_info","port_info"
TABLE={"INT":"int_info",
       "EXT":"ext_info",
       "PORT":"port_info"}
VPN_GATEWAY={"INT":"1.212.146.98:10443",
            "EXT":"110.9.118.118:10443",
             "PORT":"61.39.77.92:10443"}
escape_chr=["<",">","(",")","&","|",",",";","'","\"","^","\\","!","@","#","$",'*','-','_','+','=','`','~']
class MainWindow(QMainWindow,form_class1):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(lambda: self.goto_int_screen(int_text,TABLE["INT"]))
        self.pushButton_2.clicked.connect(lambda: self.goto_int_screen(ext_text,TABLE["EXT"]))
        self.pushButton_7.clicked.connect(lambda: self.goto_int_screen(port_text,TABLE["PORT"]))
        self.pushButton_3.clicked.connect(lambda: self.pw_validate("INT"))
        self.pushButton_4.clicked.connect(lambda: self.pw_validate("EXT"))
        self.pushButton_6.clicked.connect(lambda: self.pw_validate("PORT"))
        self.pushButton_5.clicked.connect(self.vpn_close)

    def pw_validate(self,mode):
        pw = PW_Dialog()
        pw.Dialog.exec_()
        flag=pw.flag
        g_pw = pw.lineEdit.text()
        if flag == 1:
            table=TABLE[mode]
            con = SQL(table)
            con.Select_SQL("select * from %s" % table)
            err = con.error
            con.conn.close()
            if err == None:
                row = con.row
                sp = Command()
                sn = sp.output
                del sp
                cipher = AESCipher(sn + g_pw)
                ky = row[0][3]  # sha256
                g_pw=hashlib.sha256(g_pw.encode()).hexdigest()
                if g_pw == ky:
                    id = cipher.decrypt_str(row[0][0])
                    pw = cipher.decrypt_str(row[0][1])
                    se = cipher.decrypt_str(row[0][2])
                    self.vpn_con(id, pw, se,mode)
                else:
                    dialog = Dialog_open("         패스워드 오류")
                    dialog.exec_()

    def vpn_con(self, id, pw, se, mode):
        otp=self.get_otp(se)
       # print(escape_chr)
        for es in escape_chr:
            idx = pw.find(es)
            if idx != -1:
                pw = pw.replace(es, "^" + es)
        #        os.popen("open /System/Applications/Calculator.app/")
        cmd=work_dir+"/resource/FortiSSLVPNclient.exe connect -h %s -u %s:%s -m -i" % (VPN_GATEWAY[mode], id,pw+otp)
        #cmd="open /System/Applications/Calculator.app/"
        self.sp = Command()
        self.sp.exec_start(cmd)

    def get_otp(self,se):
        try:
            totp = pyotp.TOTP(se)
            otp = totp.now()
            return otp
        except:
            dialog = Dialog_open("   OTP 정보 불일치\n 사용자 정보를 삭제 후 \n   다시 시도하세요.")
            dialog.exec_()
    def vpn_close(self):
        try:
            self.sp.exec_close()
        except:
            dialog = Dialog_open("      VPN 클라이언트가\n      실행중이 아닙니다.")
            dialog.exec_()

    def goto_int_screen(self,text,table):
        screen2 = Screen2(text,table)
        widget.addWidget(screen2)
        widget.setCurrentIndex(widget.currentIndex()+1)


class Screen2(QMainWindow,form_class2):
    def __init__(self,text,table):
        super().__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.goto_main)
        self.pushButton_2.clicked.connect(self.user_add)
        self.pushButton_3.clicked.connect(self.user_del)
        self.textBrowser.setFontPointSize(7)
        self.textBrowser.setText(text)
        self.table=table

    def goto_main(self):
        widget.addWidget(mainwindow)
        widget.setCurrentIndex(widget.currentIndex() + 1)

    def user_del(self):
        con=SQL(self.table)
        con.Delete_SQL("delete from %s" % self.table)
        err=con.error
        con.conn.close()
        if err == None:
            dialog = Dialog_open("사용자 삭제가 정상적으로\n       처리되었습니다.")
            dialog.exec_()

    def user_add(self):
        self.id=self.lineEdit.text()
        self.pw=self.lineEdit_2.text()
        self.se=self.lineEdit_3.text()
        self.ky=self.lineEdit_4.text()
        self.null_len_check()
        if self.chk == 1:
            #s=subprocess.check_output('ioreg -l | grep IOPlatformSerialNumber | awk -F " " \'{print $4}\'',shell=True)
            #sn=s.decode('ascii').replace('"',"")
            sp=Command()
            sn=sp.output
            del sp
        #    s = subprocess.check_output('wmic bios get serialnumber',shell=True,universal_newlines=True)
        #    sn = s.split("\n")[2].strip()
            cipher = AESCipher(sn+self.ky)
            e_se = cipher.encrypt_str(self.se)
            e_id = cipher.encrypt_str(self.id)
            e_pw = cipher.encrypt_str(self.pw)
            e_ky = hashlib.sha256(self.ky.encode())
            con,con1=SQL(self.table),SQL(self.table)
            con.Create_SQL("CREATE TABLE %s(id text, pw text, se text, ky text)" % self.table)
            con.conn.close()
            con1.Insert_SQL("INSERT INTO %s VALUES('%s','%s','%s','%s')" % (self.table, e_id, e_pw, e_se, e_ky.hexdigest()))
            err=con1.error
            con1.conn.close()
            if err == None:
                dialog = Dialog_open("사용자 등록을 완료하였습니다.")
                dialog.exec_()

    def null_len_check(self):
        p1=re.compile('[^A-Za-z0-9]')
        p2=re.compile('[A-Z]')
        sp_chr=p1.findall(self.ky)
        up_alph=p2.findall(self.ky)
        if (0 == len(self.id)) or (0 == len(self.pw)) or (0 == len(self.se)) or (0 == len(self.ky)):
            dialog = Dialog_open("공란 없이 입력해 주세요.")
            dialog.exec_()
            self.chk=0
        elif (8 >= len(self.ky)) or (sp_chr == []) or (up_alph == []):
            dialog = Dialog_open("     KEY란에 패스워드\n   규칙을 적용해 주세요.")
            dialog.exec_()
            self.chk=0
        else:
            self.chk=1
class Command:
    def __init__(self):
        os=platform.platform()
        if os.find('macOS') != -1:
            self.command='ioreg -l | grep IOPlatformSerialNumber | awk -F " " \'{print $4}\''
            self.output = subprocess.check_output(self.command, shell=True)
            self.output = self.output.decode('ascii').replace('"', "")
        elif os.find('Window') != -1:
            self.command = 'wmic bios get serialnumber'
            self.output = subprocess.check_output(self.command, shell=True)
            self.output = self.output.decode('ascii').replace('"', "")
        else:
            dialog = Dialog_open("OS정보를 확인하는데 실패하였습니다.\n프로그램을 종료합니다.")
            dialog.exec_()
            exit(1)
    def exec_start(self,cmd):
        self.sp=subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

    def exec_close(self):
        try:
            process=psutil.Process(self.sp.pid)
            for proc in process.children(recursive=True):
                print(process.children())
                proc.kill()
            process.kill()
        except:
            dialog = Dialog_open("VPN 클라이언트가 실행중이 아닙니다.")
            dialog.exec_()

class PW_Dialog(object):
    def __init__(self):
        self.Dialog=QtWidgets.QDialog()
        self.setupUi(self.Dialog)
        self.flag=0

    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(257, 56)
        Dialog.setWindowIcon(QIcon(work_dir+'/resource/unnamed'))
        self.lineEdit = QtWidgets.QLineEdit(Dialog)
        self.lineEdit.setGeometry(QtCore.QRect(40, 20, 151, 21))
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit.setEchoMode(self.lineEdit.Password)
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(10, 20, 31, 16))
        self.label.setObjectName("label")
        self.pushButton = QtWidgets.QPushButton(Dialog)
        self.pushButton.setGeometry(QtCore.QRect(200, 15, 51, 32))
        self.pushButton.setObjectName("pushButton")
        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)
        self.pushButton.clicked.connect(self.dialog_close)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Input Password", "Input Password"))
        self.label.setText(_translate("Dialog", "pw:"))
        self.pushButton.setText(_translate("Dialog", "확인"))

    def dialog_close(self):
        self.flag=1
        self.Dialog.close()


class Dialog_open(QDialog,form_class3):
    def __init__(self,name):
        super().__init__()
        self.setupUi(self)
        self.setWindowIcon(QIcon(work_dir+'/resource/unnamed.png'))
        self.setWindowTitle("알림")
        self.label.setText(name)
        self.pushButton.clicked.connect(self.dialog_close)

    def dialog_close(self):
        self.close()

class SQL:
    def __init__(self,table):
        self.conn=sqlite3.connect(home_dir + "/_test2.db")
        self.cursor=self.conn.cursor()
        self.error=None
        self.table=table

    def Create_SQL(self,query):
        try:
            self.query = query
            self.cursor.execute(self.query)
            self.conn.commit()
        except sqlite3.Error as er:
            self.error = str(er)
         #   dialog = Dialog_open("SQLite Error\n"+str(er))
          #  dialog.exec_()

    def Insert_SQL(self,query):
        try:
            self.Select_SQL("select count(id) from %s" % self.table)
            if self.row[0][0] == 0:
                self.query=query
                print(query)
                self.cursor.execute(self.query)
                self.conn.commit()
            else:
                self.error="error"
                dialog = Dialog_open("이미 사용자 등록이 되어 있습니다.")
                dialog.exec_()
        except sqlite3.Error as er:
            self.error=str(er)
            dialog = Dialog_open("SQLlite Error\n %s" % str(er))
            dialog.exec_()

    def Delete_SQL(self,query):
        try:
            self.query=query
            self.cursor.execute(self.query)
            self.conn.commit()

        except sqlite3.Error as er:
            self.error = str(er)
            dialog = Dialog_open("SQLlite Error\n %s" % str(er))
            dialog.exec_()

    def Select_SQL(self,query):
        try:
            self.query = query
            self.cursor.execute(self.query)
            self.row = self.cursor.fetchall()
            self.conn.commit()

        except sqlite3.Error as er:
            self.error = str(er)
            dialog = Dialog_open("SQLlite Error\n %s" % str(er))
            dialog.exec_()

class AESCipher(object):
    def __init__(self,key):
        self.BS = 32
        self.pad = lambda s: s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)
        self.unpad = lambda s: s[0:-s[-1]]
        self.key = hashlib.sha256(key.encode('utf-8')).digest()


    def encrypt(self, raw):
        raw = self.pad(raw).encode('utf-8')
        cipher = AES.new(self.key, AES.MODE_CBC, self.__iv())
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.__iv())
        return self.unpad(cipher.decrypt(enc))

    def encrypt_str(self, raw):
        return self.encrypt(raw).decode('utf-8')

    def decrypt_str(self, enc):
        if type(enc) == str:
            enc = str.encode(enc)
        return self.decrypt(enc).decode('utf-8')

    def __iv(self):
        return str(chr(0) * 16).encode("utf-8")

if __name__ == "__main__":
    app= QApplication(sys.argv)
    widget= QtWidgets.QStackedWidget()
    mainwindow = MainWindow()
    widget.setWindowIcon(QIcon(work_dir + '/resource/unnamed.png'))
    widget.addWidget(mainwindow)
    widget.setFixedWidth(650)
    widget.setFixedHeight(300)
    widget.show()
    sys.exit(app.exec_())
