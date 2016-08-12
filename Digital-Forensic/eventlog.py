import re
import sqlite3
import mmap
import contextlib
from Evtx.Evtx import FileHeader
from Evtx.Views import evtx_file_xml_view
from xml.etree.ElementTree import  parse

# global
sqlname = "result.db"ㅁ

class ykei:
    def __init__(self, xml):
        self.eID = str()    # 이벤트 로그 내용 : 이벤트 로그 ID로 내용을 식별할 수 있음 
        self.sTime = str()  # start time
        self.eTime = str()  # end time
        self.uname = str()  # user name
        self.ip = str()     # ip address
        self.port = str()   # port number
        f = open("evtx.xml", "w")   # python-evtx 모듈을 사용하기 위한 파일 저장 
        f.write(xml)
        f.close()

    def parsingXml(self):   # xml 정보를 가져와서 필요한 내용을 파싱하여 주는 메소드 
        tree = parse("evtx.xml") 
        root = tree.getroot()   # xml의 트리 구조에서 root를 획득 
        ns = re.findall('({[\w]*.*})', root.tag)[0] # xml의 namespace를 파싱 
        system = root.findall('%sSystem' % ns)[0]   # 하위 구조로 이동 
        eventID = system.findall('%sEventID' % ns)[0] # system 밑 구조로 이동 

        if eventID.text == '4624': # logon success
            print "eventID : " + eventID.text
            self.eID = eventID.text
            SystemTime = system.findall('%sTimeCreated' % ns)[0] #TimeCreated가 tag인 부분을 찾아서 반환 
            print "SystemTime : " + SystemTime.attrib['SystemTime']
            self.sTime = SystemTime.attrib['SystemTime']

        elif eventID.text == '4634': # logoff success
            print "eventID : " + eventID.text
            self.eID = eventID.text
            SystemTime = system.findall('%sTimeCreated' % ns)[0] #TimeCreated가 tag인 부분을 찾아서 반환 
            print "SystemTime : " + SystemTime.attrib['SystemTime']
            self.eTime = SystemTime.attrib['SystemTime']

        else:
            return 0

        for eventdata in root.findall('%sEventData' % ns): # root 밑의 eventdata 구조로 이동 
            if not eventdata._children.__len__():   # eventdata 구조가 없는 경우에는 탈출 
                break

            for data in eventdata.findall('%sData' % ns): # eventdata 하위 구조의 data를 찾음 
                # 각각 파싱 
                if data.attrib['Name'] == 'TargetUserName':
                    print "TargetUserName : " + data.text
                    self.uname = data.text

                if data.attrib['Name'] == 'IpAddress':
                    print "IpAddress : " + data.text
                    self.ip = data.text

                if data.attrib['Name'] == 'IpPort':
                    print "IpPort : " + data.text
                    self.port = data.text

    def insertDB(self, no): # db에 데이터 삽입 
        con = sqlite3.connect(sqlname)  # database open
        con.text_factory = str  # encoding
        cursor = con.cursor()

        cursor.execute("INSERT INTO eventlog VALUES(?,?,?,?,?,?,?)", (no, self.eID, self.sTime, self.eTime, self.uname, self.ip, self.port))
        con.commit()  # database update
        con.close()


def EvtxtoXml(path):    # event log 파일인 evtx를 xml 형태로 변형해서 처리
    no = 0
    with open(path, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0,
                                          access=mmap.ACCESS_READ)) as buf:
            fh = FileHeader(buf, 0x0)
            for xml, record in evtx_file_xml_view(fh):
                print "================================"
                el = ykei(xml)  # xml로 변형된 내용을 이용해서 객체 생성 
                if el.parsingXml() != 0:    # 로그온-오프 로그가 아니면 db에 삽입하지 않음 
                    no += 1 # 번호 증가 
                    el.insertDB(no)

def main():

    con = sqlite3.connect(sqlname)  # database create
    con.text_factory = str()
    cursor = con.cursor()

    sql = "CREATE TABLE eventlog(No int, eID text, sTime text, eTime text, uname text, ip text, port text)"
    cursor.execute(sql)  # execute query
    con.close()
    EvtxtoXml("G:\\Windows\\System32\\winevt\\Logs\\Security.evtx")
    # logon = 4624, logoff = 4634

if __name__ == "__main__":
    main()