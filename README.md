# Python-Parser-PE-files

The PE file parser was implemented in the Python 3.7 programming language for legitimate installation files, Trojan downloaders, and Trojan droppers.
The extraction of the PE header attributes was carried out using the pefile library. All of their attributes were retrieved from DOS, FILE and OPTIONAL file headers. In addition, the parser receives the attributes of the PE file, which are responsible for information about it. Such attributes, for example, are CompanyName, FileVersion, FileDescription, and others, and attributes about information about resource directories in the file section are IMAGE_RESOURCE_DIRECTORY. Such directories are, for example, RT_ICON, RT_VERSION, RT_MANIFEST, etc.
The program carries out both parsing of each PE-file and parsing with the subsequent calculation of the quantitative and percentage parameter for each attribute of the DOS, FILE and OPTIONAL headers.
