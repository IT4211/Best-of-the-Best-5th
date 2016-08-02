#-*- coding: utf-8 -*-

import re
import ssl
import base64
from datetime import date
from httplib2 import Http
from gmail import Gmail
from GoogleMap import *
from GPSInfo import *
from SQLite3 import *
from Hash import *
from CSV import *

class fl0ckfl0ck:

    def __init__(self, email):
        self.email = email
        self.date = ""
        self.path = ""
        self.error = str()
        self.file = "N/A"
        self.md5hash = "N/A"
        self.sha1hash = "N/A"
        self.gps_lat = "N/A"
        self.gps_lon = "N/A"
        self.gmap = list()
        self.fullurl = "N/A"

    def GetGmail(self):
        self.email.fetch()
        contents = self.email.body
        self.date = self.email.sent_at
        if 'Content-Transfer-Encoding' in self.email.headers:
            EncodingType = self.email.headers['Content-Transfer-Encoding']
        else:
            EncodingType = 0

        #checking base64
        if EncodingType == 'base64':   # true : base64 decoding
            decodeurl = base64.b64decode(contents)  # decoding
            self.shorturl = re.findall('(https?:\/\/.*[.].*\/[\w]*)', decodeurl)[0] # parcing url from decoded body
            if self.shorturl.split('/')[2] == "grep.kr":                            # special case, grep.kr url
                self.shorturl = re.findall('(http:\/\/grep.kr\/[\w]{4})', self.shorturl)[0] # grep.kr regex, get url
            elif self.shorturl.split('/')[2] == "goo.gl":                           # special case, goo.gl url
                self.shorturl = re.findall('(https?:\/\/.*[.].*\/[\w]{6})', self.shorturl)[0]   # goo.gl regex, get url
        #checking exist member 'Content-Transfer-Encoding'
        elif EncodingType == 0:
            contents = self.email.html  # html
            self.shorturl = re.findall('<a\s*href=[\'|"](.*?)[\'"].*?>', contents)[0]   # get url from html
            self.shorturl = re.findall('(https?:\/\/.*[.].*\/[\w]*)', self.shorturl)[0]     # get url from parced html url

        else:
            self.shorturl = re.findall('(https?:\/\/.*[.].*\/[\w]*)', contents)[0]  # get url from body
        print "[email body] " + self.shorturl


    def ShortToFull(self):
        request = Http()    # create http object
        request.follow_redirects = False
        response, contents = request.request(self.shorturl) #shorturl request and get fullurl from response
        try:
            if response.status == 404:  # status 404 is link break
                self.fullurl = "N/A"
            self.fullurl = response['location']
        except KeyError as err:
            return 0
        return 1

    def GetImage(self):
        originURL = self.fullurl

        getfile = originURL.split('/')[-1]  # getfilename from fullurl
        decode_filename = urllib.unquote(getfile)   # decoding filename
        photo = decode_filename.decode('utf-8').encode('euc-kr')    # transfer filename : korean
        decode_originURL = urllib.unquote(originURL).decode('utf-8').encode('euc-kr')   # transfer url : korean

        ssl._create_default_https_context = ssl._create_unverified_context # for https connection

        self.file = photo   # set object member 'file'

        imagefile = urllib.URLopener()
        try:    # 인코딩 문제때문에 다르게 인코딩된 url로 파일 다운로드
            urllib.urlretrieve(decode_originURL, self.path + photo)
            try:
                imagefile.retrieve(originURL, self.path + photo)
            except IOError as e:
                pass
        except IOError as er:
            pass

    def GetGPS(self):
        get_gps_info(self)

    def GetHash(self):
        get_hash(self)

    def OutCSV(self):
        out_csv(self)

    def OutSQLite(self, path):
        out_sqlite(self, path)

    def MakeGmap(self):
        return str(self.gps_lat) +','+ str(self.gps_lon)

def main():
    path = "C:\\Users\\L.SeonHo\\Desktop\\result\\"
    gmaps = list()  # for location
    gmap_path = str()   # for full path
    g = Gmail()
    g.login('bob5leesh', 'rlayuna#0905')
    if not os.path.isdir(path):
        os.mkdir(path)
    set_sqlite(path)

    for i in range(16, 30):
        mailday = date(2016, 7, i)
        daypath =  "C:\\Users\\L.SeonHo\\Desktop\\result\\" + str(mailday) +"\\"    # for create day folder
        daygmap = list()    # create day gmap
        if not os.path.isdir(daypath):
            os.mkdir(daypath)   # create folder
        emails = g.inbox().mail(on = mailday, sender = 'fl0ckfl0ck@hotmail.com')

        for email in emails:
            flock = fl0ckfl0ck(email) # one mail routine
            flock.path = daypath
            flock.GetGmail()
            gmap_path = flock.path
            if flock.ShortToFull() != 0: # in : success get full url / out : fail get full url
                flock.GetImage()
                flock.GetHash()
                flock.GetGPS()
                # check exist gps info from file
                if str(flock.gps_lat) == 'None' or str(flock.gps_lon) == 'None':
                    pass
                elif str(flock.gps_lat) == 'N/A' or str(flock.gps_lon) == 'N/A':
                    pass
                else:
                    gmaps.append(flock.MakeGmap())       # setting day gmap
                    daygmap.append(flock.MakeGmap())     # setting full gmap
            flock.OutCSV()  # create CSV file
            flock.OutSQLite(path)   # create SQLite database
        if len(daygmap) != 0:
            get_googlemap(daygmap, gmap_path)   # get day gmap
        get_googlemap(gmaps, path)  # get full gmap

if __name__ == "__main__":
    main()