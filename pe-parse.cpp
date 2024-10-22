#include <iostream>
#include <windows.h>
#include <fstream>
using namespace std;

int peParse(const char* peFile) {
	ifstream file(peFile, ios::binary);

	IMAGE_DOS_HEADER dos_header;
	file.read(reinterpret_cast<char*>(&dos_header), sizeof(IMAGE_DOS_HEADER));

	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "File could not be opened, error: 0x" << GetLastError() << endl;
		return EXIT_FAILURE;
	}

	file.seekg(dos_header.e_lfanew, ios::beg);

	IMAGE_NT_HEADERS ntHeader;
	file.read(reinterpret_cast<char*>(&ntHeader), sizeof(IMAGE_NT_HEADERS));

	if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
		cout << "NT header of the file is invalid, error: 0x" << GetLastError() << endl;
		return EXIT_FAILURE;
	}

	//Entry p., Image base, number of sec.
	cout << "PE file was read success" << endl;
	cout << "The entry point: " << ntHeader.OptionalHeader.AddressOfEntryPoint << endl;
	cout << "The image base address: " << ntHeader.OptionalHeader.ImageBase << endl;
	cout << "The number of section: " << ntHeader.FileHeader.NumberOfSections << endl;

	for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++) {

		IMAGE_SECTION_HEADER secHeader;
		file.read(reinterpret_cast<char*>(&secHeader), sizeof(IMAGE_SECTION_HEADER));

		cout << "Name" << secHeader.Name << endl;
		cout << "Start Address 0x" << secHeader.VirtualAddress << endl;
		cout << "Size 0x" << secHeader.Misc.VirtualSize << endl;
	}

	file.close();
}



int main(int argc, const char* argv[]) {
	peParse(argv[1]);
	return EXIT_SUCCESS;
}
