#-*- coding: utf-8 -*-
import sqlite3

def set_sqlite(path):
    sqlname = path + "result.db"
    con = sqlite3.connect(sqlname)  # database create
    con.text_factory = str()
    cursor = con.cursor()

    sql = "CREATE TABLE result(" \
          "Send_Date[UTC] text, " \
          "URL text, " \
          "File_Name text, " \
          "MD5 text, " \
          "SHA1 text, " \
          "latitude text, " \
          "longitude text)"
    cursor.execute(sql)     # execute query


def out_sqlite(self, path):
    sqlname = path + "result.db"
    con = sqlite3.connect(sqlname)  # database open
    con.text_factory = str          # encoding
    cursor = con.cursor()

    cursor.execute("INSERT INTO result VALUES(?,?,?,?,?,?,?)", (self.date, self.shorturl, self.file.decode('euc-kr'), self.md5hash, self.sha1hash, self.gps_lat, self.gps_lon))
    con.commit()    # database update
    con.close()