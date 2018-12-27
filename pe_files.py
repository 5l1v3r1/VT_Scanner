import os
import numpy as np
import pefile
import pandas as pd
import shutil

def sub_filename(path, num):
    sub_filename = {}
    filename = os.listdir(path)
    np.random.shuffle(filename)
    for k in range(2):
        mini_filename = filename[k*num: (k+1)*num]
        sub_filename[str(k)] = mini_filename

    return sub_filename

def pe2vec(path, sub_filename):
    dataset = {}
    for k in range(2):
        mini_dataset = {}
        for dir in sub_filename[str(k)]:
            try:
                file_path = os.path.join(path, dir)
                pe = PEFile(file_path)
                mini_dataset[str(dir)] = pe.Construct()
            except Exception as e:
                print (e)

        dataset[str(k)] = mini_dataset

    return dataset

def PE_Files(dataset):
    fullpath = os.path.join
    start_directory = "/home/ariefhakimaskar/Desktop/VT_Scanner_MF/VirusShare/"
    PE_path = "/home/ariefhakimaskar/Desktop/VT_Scanner_MF/PE/"
    Other_path = "/home/ariefhakimaskar/Desktop/VT_Scanner_MF/Other/"
    for k in range(2):
        df = pd.DataFrame(dataset[str(k)])
        for filename in df:
            for dirname, dirnames, filenames in os.walk(start_directory):
                for filename_source in filenames:
                    source = fullpath(dirname, filename_source)
                    if filename_source == filename:
                       shutil.copy(source, fullpath(PE_path, filename_source))
                    else:
                        shutil.copy(source, fullpath(Other_path, filename_source))

class PEFile(object):
    def __init__(self, filename):
        self.pe = pefile.PE(filename, fast_load = True)
        self.filename = filename
        self.DebugSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size
        self.DebugRVA = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].VirtualAddress
        self.ImageVersion = self.pe.OPTIONAL_HEADER.MajorImageVersion
        self.OsVersion = self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        self.ExportRVA = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
        self.ExportSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        self.IATRVA = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].VirtualAddress
        self.ResSize = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size
        self.LinkerVersion = self.pe.OPTIONAL_HEADER.MajorLinkerVersion
        self.NumberOfSections = self.pe.FILE_HEADER.NumberOfSections
        self.StackReserveSize = self.pe.OPTIONAL_HEADER.SizeOfStackReserve
        self.Dll = self.pe.OPTIONAL_HEADER.DllCharacteristics

    def Construct(self):
        sample = self.__dict__        #这个地方是实例属性，for循环也就是去遍历这个实例属性。

        return sample

sub_filename = sub_filename(r"/home/ariefhakimaskar/Desktop/VT_Scanner_MF/VirusShare/", 1000)
dataset = pe2vec(r"/home/ariefhakimaskar/Desktop/VT_Scanner_MF/VirusShare/", sub_filename)
PE_Files(dataset)

