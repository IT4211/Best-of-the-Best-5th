import os
import csv
from collections import Counter
from operator import itemgetter
import pyewf    #ewf 파일을 읽기 위한 모듈 포함
import pytsk3   #파일시스템을 읽고 필요한 내용을 추출하기 위한 모듈 포함

ext_list = [] #확장자 정보를 입력받기 위한 리스트 선언

'''
E01 이미지 파일을 읽어 들이기 위해서 ewf_Img_Info 클래스를 정의하여 준다.
이때 생성자에서 super를 사용해서 pytsk3로 넘겨서 사용할 수 있게 해준다.
'''

class ewf_Img_Info(pytsk3.Img_Info):
  def __init__(self, ewf_handle):
    self._ewf_handle = ewf_handle
    super(ewf_Img_Info, self).__init__(
        url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

  def close(self):
    self._ewf_handle.close()

  def read(self, offset, size):
    self._ewf_handle.seek(offset)
    return self._ewf_handle.read(size)

  def get_size(self):
    return self._ewf_handle.get_media_size()

def recursive(directoryObject, parentPath, output):     # 하위 디렉토리까지 탐색하기 위한 recursive 함수 구현
    for entryObject in directoryObject:
        if entryObject.info.name.name in [".", ".."]:   # 디렉토리 명이 .과 ..인 경우는 제외
            continue

        try:
            f_type = entryObject.info.meta.type         # 오브젝트의 타입을 확인한다.
        except:
            #print "Cannot retrive type : " + entryObject.info.name.name # 타입을 확인 할 수 없는 경우
            continue

        try:
            filepath = '/%s/%s' % ('/'.join(parentPath), entryObject.info.name.name)    # 다음 디렉터리 경로를 만들어 줌
            ext = os.path.splitext(filepath)[-1]    # 확장자를 분리하여 줌
            filesize = entryObject.info.meta.size   # 파일의 크기를 구해준다.
            ext_list.append(ext)                    # 구한 확장자는 리스트에 넣어준다.

            if  f_type == pytsk3.TSK_FS_META_TYPE_DIR:  # 타입이 디렉토리 일 경우 재귀 호출을 수행
                sub_directory = entryObject.as_directory()
                parentPath.append(entryObject.info.name.name)
                recursive(sub_directory, parentPath, output)
                parentPath.pop(-1)
                cw = csv.writer(output, delimiter = ',')
                cw.writerow([filepath, ext])    # csv형태로 디렉토리명과 확장자 저장

            elif f_type == pytsk3.TSK_FS_META_TYPE_REG: # 일반 파일일 경우
                cw = csv.writer(output, delimiter=',')
                cw.writerow([filepath, ext, filesize])  # 파일명과 확장자, 파일 크기를 csv로 저장

        except IOError as e:
            print e
            continue

def main():
    filenames = pyewf.glob("E:\\YK_F1\\cfreds_2015_data_leakage_pc.E01")    # pyewf에서 연속된 ewf파일을 읽어 들이기 위해 .glob 사용
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)      # E01 이미지 파일에 대한 핸들을 오픈한다. (분할된 파일이 하나의 파일 처럼 열림)
    img_info = ewf_Img_Info(ewf_handle)     # ewf_Img_Info을 이용해서 이미지를 오픈한다. 객체의 생성자에서 super를 통해 pytsk 객체로 생성
    vol = pytsk3.Volume_Info(img_info)      # 이미지를 불러들여 볼륨 정보를 얻어온다. 이때 pytsk3 모듈을 사용한다.
    output = open("result.csv", 'wb')
    ext_cnt = open("ext_cnt.txt", 'w')
    for part in vol:
        print part.addr, part.desc, part.start, part.len    # 볼륨 정보를 얻어와서 출력
        if part.len > 2048:
            fs = pytsk3.FS_Info(img_info, offset = part.start*vol.info.block_size)  # 각 볼륨에 대한 파일시스템 정보를 얻어 온다.
            directoryObject = fs.open_dir('/')  # 루트 디렉토리부터 오브젝트를 연다.
            recursive(directoryObject, [], output)  # 디렉터리 탐색 시작
            pass

    cnt = Counter(ext_list)     # 확장자별로 개수를 세기 위한 Counter 이용
    for i in sorted(cnt.items(), key=itemgetter(1), reverse=True):  # 확장자 갯수별로 정렬
        ext_cnt.write(str(i) + '\n')


if __name__ == "__main__":
    main()
