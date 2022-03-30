import os
import pefile

file_name=['sample_qwrty_dk2','sample_vg655_25th.exe']

for file in file_name:
	path = os.path.dirname(__file__)
	path = path + '/MALWR2/' + file
	pe = pefile.PE('./MALWR2/' + file)
	
	for section in pe.sections:
		print('\n\tSection:')
		print(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)

	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		# print('Function Calls:')
		print('DLL Calls: ', entry.dll)
		print('Function Calls:')
		for function in entry.imports:
			print('\t', function.name)
	
	print('\n\tHeader: ', pe.FILE_HEADER)
	print('\n\tHash: ', pe.get_rich_header_hash('sha256'))