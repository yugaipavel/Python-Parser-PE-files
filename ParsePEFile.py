import os
import csv
import math
import shutil
import random
import pefile
from pefile import PE
from ntpath import basename

"""
Examples of directory's resources:
'RT_ACCELERATOR', 'RT_BITMAP', 'RT_CURSOR', 'RT_DIALOG', 'RT_GROUP_CURSOR',\
'RT_GROUP_ICON', 'RT_ICON', 'RT_MANIFEST', 'RT_MENU', 'RT_RCDATA', 'RT_STRING', 'RT_VERSION', 'AVI',\
'BIN', 'CONFIG', 'DICTIONARY', 'DLL', 'EXE', 'FONT', 'IMAGE_FILE' 'GIF', 'JSON', 'PNG', 'RTF_FILE',\
'STRINGS', 'TXT', 'UNICODEDATA', 'XML', 'UNKNOWN_RESOURCE'
"""
"""
Examples of directory's resources:
'CompanyName', 'FileVersion', 'FileDescription', 'InternalName', 'LegalCopyright',\
'OriginalFilename', 'ProductName', 'ProductVersion'
"""

# begin of ParsePE class
class ParsePE:

    def __init__(self):

        self.ListRows = []
        self.ListAllFields = []

        self.ListFieldsDOS = ['e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 'e_maxalloc',\
        'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc', 'e_ovno', 'e_res', 'e_oemid', 'e_oeminfo', 
        'e_res2', 'e_lfanew']

        self.ListFieldsFILE = ['Machine','NumberOfSections', 'TimeDateStamp','PointerToSymbolTable',\
        'NumberOfSymbols','SizeOfOptionalHeader','Characteristics']

        self.ListFieldsOPTIONAL = ['Magic','MajorLinkerVersion','MinorLinkerVersion','SizeOfCode',\
        'SizeOfInitializedData','SizeOfUninitializedData','AddressOfEntryPoint',\
        'BaseOfCode','BaseOfData','ImageBase','SectionAlignment','FileAlignment','MajorOperatingSystemVersion',\
        'MinorOperatingSystemVersion','MajorImageVersion','MinorImageVersion','MajorSubsystemVersion',\
        'MinorSubsystemVersion','Reserved1','SizeOfImage','SizeOfHeaders','CheckSum','Subsystem',\
        'DllCharacteristics','SizeOfStackReserve','SizeOfStackCommit','SizeOfHeapReserve','SizeOfHeapCommit',\
        'LoaderFlags', 'NumberOfRvaAndSizes']

        self.ListFieldsDirectoryEntryResource = ['RT_ICON', 'RT_VERSION', 'RT_MANIFEST']

        self.ListFieldsInformationFile = ['CompanyName', 'FileDescription', 'FileVersion', 'LegalCopyright',\
        'ProductName', 'ProductVersion']

        self.ListAllFields.append('TypeFile')

        for elem in self.ListFieldsDOS:
            self.ListAllFields.append(elem)

        for elem in self.ListFieldsFILE:
            self.ListAllFields.append(elem)

        for elem in self.ListFieldsOPTIONAL:
            self.ListAllFields.append(elem)

        for elem in self.ListFieldsDirectoryEntryResource:
            self.ListAllFields.append(elem)

        for elem in self.ListFieldsInformationFile:
            self.ListAllFields.append(elem)

        self.ListRows.append(self.ListAllFields)

    def _valid(self, item):
        if type(item) is bytes:
            return int.from_bytes(item, byteorder='little')
        return item

    def _parse_DOS_HEADER(self, pe_file: PE):
        
        ListValuesDOS = []

        for item in pe_file.DOS_HEADER.__dict__['__unpacked_data_elms__']:
            ListValuesDOS.append(self._valid(item))

        return ListValuesDOS

    def _parse_FILE_HEADER(self, pe_file: PE):

        ListValuesFile = []

        for item in pe_file.FILE_HEADER.__dict__['__unpacked_data_elms__']:
            ListValuesFile.append(self._valid(item))

        return ListValuesFile


    def _parse_OPTIONAL_HEADER(self, pe_file: PE):

        ListValuesOPTIONAL = []

        index = 1
        baseofdata = 0

        if 'BaseOfData' not in pe_file.OPTIONAL_HEADER.__dict__.keys():
            baseofdata = 1

        for item in pe_file.OPTIONAL_HEADER.__dict__['__unpacked_data_elms__']:
            if baseofdata == 1 and index == 9:
                ListValuesOPTIONAL.append(self._valid(0))
                ListValuesOPTIONAL.append(self._valid(item))
            else:
                ListValuesOPTIONAL.append(self._valid(item))
            
            index += 1
       
        return ListValuesOPTIONAL

    def _parse_pe_headers(self, pe_file: PE, file_name, is_type):

        ListDOS = self._parse_DOS_HEADER(pe_file)
        ListFILE = self._parse_FILE_HEADER(pe_file)
        ListOPTIONAL = self._parse_OPTIONAL_HEADER(pe_file)

        ListPEheaders = []
        if is_type == 0:
            ListPEheaders.append(0)
        if is_type == 1:
            ListPEheaders.append(1)
        if is_type == 2:
            ListPEheaders.append(2)

        for elem in ListDOS:
            ListPEheaders.append(elem)

        for elem in ListFILE:
            ListPEheaders.append(elem)

        for elem in ListOPTIONAL:
            ListPEheaders.append(elem)

        return ListPEheaders


    def _parse_directory_entry_resource(self, pe):

        ListCountResources = []
        templist = []
        NameResources = []
        CountResource = []

        unknown_flag = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.name is not None:
                    name = "%s" % resource_type.name
                else:
                    name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
                if name == None:
                    name = "%d" % resource_type.struct.Id
                if hasattr(resource_type, 'directory'):

                    if self.ListFieldsDirectoryEntryResource.count(name) > 0:
                        NameResources.append(name)
                        CountResource.append(len(resource_type.directory.entries))
                    elif unknown_flag == 0:
                        NameResources.append('UNKNOWN_RESOURCE')
                        CountResource.append(len(resource_type.directory.entries))
                        unknown_flag = 1
                    else:
                        unknown_index = NameResources.index('UNKNOWN_RESOURCE')
                        CountResource[unknown_index] += len(resource_type.directory.entries)

        templist.append(NameResources)
        templist.append(CountResource)

        index = 0
        for elem in self.ListFieldsDirectoryEntryResource:
            if templist[0].count(elem) > 0:
                ListCountResources.append(templist[1][index])
                index +=1
            else:
                ListCountResources.append(0)
            
        return ListCountResources

    def _parse_version_information(self, pe_file: PE):

        is_info = 0

        ListInfoFile = []
        namefield = []
        valuefield = []

        try:
            for fileinfo in pe_file.FileInfo:
                if fileinfo[0].Key == b'StringFileInfo':
                    for st in fileinfo[0].StringTable:
                        for entry in st.entries.items():
                            is_info = 1
                            if isinstance(entry[0], bytes):
                                namefield.append(entry[0].decode())   
                            if isinstance(entry[1], bytes):
                                valuefield.append(entry[1].decode())
        except:
            pass
        
        if is_info == 1:
            for elem in self.ListFieldsInformationFile:
                if namefield.count(elem) > 0:
                    index = namefield.index(elem)
                    tempvalue = str(valuefield[index])
                    tempvalue = ''.join(tempvalue.split())
                    if tempvalue != '':
                        ListInfoFile.append(1)
                    else:
                        ListInfoFile.append(0)
                else:
                    ListInfoFile.append(0)
        else:
            for elem in self.ListFieldsInformationFile:
                ListInfoFile.append(0)

        return ListInfoFile

    def _create_csvdata_for_weka(self):
        csvfile = open('datafiles.csv', 'w')
        with csvfile:
            writer = csv.writer(csvfile, lineterminator='\n')
            writer.writerows(self.ListRows)
        csvfile.close()

    def _calculate_values(self):

        file_res_wr = open('whiteInstaller_parameters.txt', 'w')
        file_res_tdr = open('trojandropper_parameters.txt', 'w')
        file_res_tdo = open('trojandownloader_parameters.txt', 'w')
        
        if len(self.ListRows) > 1:
            i_row_first = 0
            i_row_last = 0
            i_row = 1
            while i_row < len(self.ListRows):
                
                if int(self.ListRows[i_row][0]) == 0:
                    i_row_first = i_row
                    i_column = 1
                    file_res_wr.write('--------------------WhiteInstaller--------------------\n\n')
                    while i_column < len(self.ListRows[i_row]):
                        
                        ListAttribute = []

                        while i_row < len(self.ListRows) and int(self.ListRows[i_row][0]) == 0:
                            ListAttribute.append(self.ListRows[i_row][i_column])
                            i_row += 1
                        
                        i_row_last = i_row
                        listcheck = []     
                        file_res_wr.write('[***] ' + self.ListRows[0][i_column]  + '\n')

                        for elem in ListAttribute:
                            
                            if listcheck.count(elem) == 0:
                                listcheck.append(elem)
                                file_res_wr.write(str(elem) + ': ' + str(ListAttribute.count(elem)) + '/' + str(i_row-i_row_first) + ' (' + str(ListAttribute.count(elem)*100/(i_row-i_row_first)) + '% )\n')
                            
                        file_res_wr.write('\n')
                        i_column += 1
                        i_row = i_row_first

                    file_res_wr.write('-----------------------------------------------------\n\n')
                    i_row = i_row_last
                
                elif int(self.ListRows[i_row][0]) == 1:
                    i_row_first = i_row
                    i_column = 1
                    file_res_tdr.write('--------------------TrojanDropper--------------------\n\n')
                    while i_column < len(self.ListRows[i_row]):
                        
                        ListAttribute = []

                        while i_row < len(self.ListRows) and int(self.ListRows[i_row][0]) == 1:
                            ListAttribute.append(self.ListRows[i_row][i_column])
                            i_row += 1
                        
                        i_row_last = i_row
                        listcheck = []     
                        file_res_tdr.write('[***] ' + self.ListRows[0][i_column]  + '\n')

                        for elem in ListAttribute:
                            
                            if listcheck.count(elem) == 0:
                                listcheck.append(elem)
                                file_res_tdr.write(str(elem) + ': ' + str(ListAttribute.count(elem)) + '/' + str(i_row-i_row_first) + ' (' + str(ListAttribute.count(elem)*100/(i_row-i_row_first)) + '% )\n')

                        file_res_tdr.write('\n')
                        i_column += 1
                        i_row = i_row_first

                    file_res_tdr.write('-----------------------------------------------------\n\n')
                    i_row = i_row_last

                elif int(self.ListRows[i_row][0]) == 2:
                    i_row_first = i_row
                    i_column = 1
                    file_res_tdo.write('--------------------TrojanDownloader--------------------\n\n')
                    while i_column < len(self.ListRows[i_row]):
                        
                        ListAttribute = []

                        while i_row < len(self.ListRows) and int(self.ListRows[i_row][0]) == 2:
                            ListAttribute.append(self.ListRows[i_row][i_column])
                            i_row += 1
                        
                        i_row_last = i_row
                        listcheck = []     
                        file_res_tdo.write('[***] ' + self.ListRows[0][i_column] + '\n')

                        for elem in ListAttribute:
                            
                            if listcheck.count(elem) == 0:
                                listcheck.append(elem)
                                file_res_tdo.write(str(elem) + ': ' + str(ListAttribute.count(elem)) + '/' + str(i_row-i_row_first) + ' (' + str(ListAttribute.count(elem)*100/(i_row-i_row_first)) + '% )\n')

                        file_res_tdo.write('\n')
                        i_column += 1
                        i_row = i_row_first

                    file_res_tdo.write('-----------------------------------------------------\n\n')
                    i_row = i_row_last + 1

        file_res_wr.close()
        file_res_tdr.close()
        file_res_tdo.close()

    def _get_file_info(self, paths: list, is_type: int):
        count = 0

        for file in paths:
            try:
                ListToRow = []
                ListPEheaders = []
                ListResources = []
                
                pe_file = PE(file)
                file_name = basename(file)

                ListPEheaders = self._parse_pe_headers(pe_file, file_name, is_type)    
                ListResources = self._parse_directory_entry_resource(pe_file)
                ListInformationFile = self._parse_version_information(pe_file)

                if len(ListPEheaders) + len (ListResources) + len(ListInformationFile) == len(self.ListRows[0]):
                    
                    for elem in ListPEheaders:
                        ListToRow.append(elem)
                    for elem in ListResources:
                        ListToRow.append(elem)
                    for elem in ListInformationFile:
                        ListToRow.append(elem)

                    self.ListRows.append(ListToRow)

                else:
                    print('Error of parsing file with name:', basename(file))

                count += 1
            except:
                print('Error of parsing file with name:', basename(file))
                pass

# end of ParsePE class 

def get_file_with_path(dir):

    ListFiles = []
    names = os.listdir(dir)

    for name in names:
        fullname = os.path.join(dir, name)
        if os.path.isfile(fullname):
            ListFiles.append(fullname)

    return ListFiles

def parse_pe_files_and_get_dataset():

    PathValid = 'D:\\Users\\Desktop\\WhiteInstallers\\exe'
    PathTrojanDroppers = 'D:\\Users\\Desktop\\TrojanDroppers'
    PathTrojanDownloaders = 'D:\\Users\\Desktop\\TrojanDownloaders'

    ListValid = get_file_with_path(PathValid)
    ListTrojanDroppers = get_file_with_path(PathTrojanDroppers)
    ListTrojanDownloaders = get_file_with_path(PathTrojanDownloaders)

    pp = ParsePE()

    pp._get_file_info(ListValid, 0)
    pp._get_file_info(ListTrojanDroppers, 1)
    pp._get_file_info(ListTrojanDownloaders, 2)

    pp._calculate_values()
    pp._create_csvdata_for_weka()

if __name__ == '__main__':

    parse_pe_files_and_get_dataset()