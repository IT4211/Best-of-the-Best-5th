#-*- coding: utf-8 -*-
import os
import csv


def out_csv(self):
    # result folder and date folder create
    csvname = "result.csv"
    csvpath = self.path + csvname
    if not os.path.exists(csvpath): # one time action
        csv_file = open(csvpath, "wb")
        cw = csv.writer(csv_file, delimiter=',', quotechar = '|')
        no = "연번".decode('utf-8').encode('euc-kr')
        timestamp = "시각(UTC)".decode('utf-8').encode('euc-kr')
        csvfilename = "파일명".decode('utf-8').encode('euc-kr')
        cw.writerow([no, timestamp, "Shortened URL", "Full URL", csvfilename, "GPS(Lat)", "GPS(Lon)", "MD5", "SHA1"])
        csv_file.close()

    csv_file = open(csvpath, "a+")
    cw = csv.writer(csv_file, delimiter=',', quotechar='|')
    cw.writerow(["1", self.date, self.shorturl, self.fullurl, self.file, self.gps_lat, self.gps_lon, self.md5hash, self.sha1hash])
    csv_file.close()
