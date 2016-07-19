import os
import csv
import pyewf
import pytsk3

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


def recursive(directoryObject, parentPath, output):
    for entryObject in directoryObject:
        if entryObject.info.name.name in [".", ".."]:
            continue

        try:
            f_type = entryObject.info.meta.type
        except:
            #print "Cannot retrive type : " + entryObject.info.name.name
            continue

        try:
            filepath = '/%s/%s' % ('/'.join(parentPath), entryObject.info.name.name)
            ext = os.path.splitext(filepath)[-1]
            filesize = entryObject.info.meta.size

            if  f_type == pytsk3.TSK_FS_META_TYPE_DIR:
                sub_directory = entryObject.as_directory()
                parentPath.append(entryObject.info.name.name)
                recursive(sub_directory, parentPath, output)
                parentPath.pop(-1)
                cw = csv.writer(output, delimiter = ',')
                cw.writerow([filepath, ext])

            elif f_type == pytsk3.TSK_FS_META_TYPE_REG:
                cw = csv.writer(output, delimiter=',')
                cw.writerow([filepath, ext, filesize])


        except IOError as e:
            print e
            continue

def main():
    filenames = pyewf.glob("E:\\YK_F1\\cfreds_2015_data_leakage_pc.E01")
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)
    img_info = ewf_Img_Info(ewf_handle)
    vol = pytsk3.Volume_Info(img_info)
    output = open("result.csv", 'wb')
    for part in vol:
        print part.addr, part.desc, part.start, part.len
        if part.len > 2048:
            fs = pytsk3.FS_Info(img_info, offset = part.start*vol.info.block_size)
            directoryObject = fs.open_dir('/')
            recursive(directoryObject, [], output)
            pass

if __name__ == "__main__":
    main()
    