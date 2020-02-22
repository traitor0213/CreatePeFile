#include <stdio.h>
#include <windows.h>

#include "shellcode.h"

int main(int argc, char **argv)
{
	IMAGE_DOS_HEADER DosHeader;
	ZeroMemory(&DosHeader, sizeof(DosHeader));
	DosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER);
	DosHeader.e_magic = 'ZM';

	IMAGE_NT_HEADERS32 NtHeaders32;
	ZeroMemory(&NtHeaders32, sizeof(NtHeaders32));
	NtHeaders32.FileHeader.Characteristics = 0x10F; //executable, 32bit, etc
	NtHeaders32.FileHeader.Machine = 0x014C;		//32bit executable
	NtHeaders32.FileHeader.NumberOfSections = 1;	//.text section only
	NtHeaders32.FileHeader.NumberOfSymbols = 0;
	NtHeaders32.FileHeader.PointerToSymbolTable = 0;
	NtHeaders32.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
	NtHeaders32.FileHeader.TimeDateStamp = 0;

	NtHeaders32.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	NtHeaders32.OptionalHeader.AddressOfEntryPoint = 0x1000;
	NtHeaders32.OptionalHeader.BaseOfCode = 0x1000;
	NtHeaders32.OptionalHeader.BaseOfData = 0x0000;
	NtHeaders32.OptionalHeader.ImageBase = 0x01000000;
	NtHeaders32.OptionalHeader.SectionAlignment = 0x1000;
	NtHeaders32.OptionalHeader.FileAlignment = 0x200;
	NtHeaders32.OptionalHeader.MajorOperatingSystemVersion = 0x5;
	NtHeaders32.OptionalHeader.MinorOperatingSystemVersion = 0x1;
	NtHeaders32.OptionalHeader.MajorImageVersion = 0x5;
	NtHeaders32.OptionalHeader.MinorImageVersion = 0x1;
	NtHeaders32.OptionalHeader.MajorSubsystemVersion = 0x4;
	NtHeaders32.OptionalHeader.MinorSubsystemVersion = 0x0;
	NtHeaders32.OptionalHeader.Win32VersionValue = 0;
	NtHeaders32.OptionalHeader.SizeOfImage = 0x14000;
	NtHeaders32.OptionalHeader.SizeOfHeaders = 0x400;
	NtHeaders32.OptionalHeader.CheckSum = 0;
	NtHeaders32.OptionalHeader.Subsystem = 0x2;
	NtHeaders32.OptionalHeader.DllCharacteristics = 0x8000;
	NtHeaders32.OptionalHeader.SizeOfStackReserve = 0x40000;
	NtHeaders32.OptionalHeader.SizeOfStackCommit = 0x10000;
	NtHeaders32.OptionalHeader.SizeOfHeapReserve = 0x100000;
	NtHeaders32.OptionalHeader.SizeOfHeapCommit = 0x1000;
	NtHeaders32.OptionalHeader.LoaderFlags = 0;
	NtHeaders32.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	NtHeaders32.Signature = 'EP'; 

	int PointerOfTextSection = 0x200;
	int PaddingDistance = sizeof(DosHeader) + sizeof(NtHeaders32) + sizeof(IMAGE_SECTION_HEADER);

	int PaddingSize = PointerOfTextSection - PaddingDistance;

	IMAGE_SECTION_HEADER SectionHeader;
	ZeroMemory(&SectionHeader, sizeof(SectionHeader));
	memcpy(SectionHeader.Name, "root", sizeof(SectionHeader.Name));
	SectionHeader.VirtualAddress = 0x1000;
	SectionHeader.SizeOfRawData = sizeof(SHELLCODE);
	SectionHeader.PointerToRawData = PointerOfTextSection;
	SectionHeader.Characteristics = 0x60000020;
	SectionHeader.Misc.VirtualSize = sizeof(SHELLCODE);

	printf("%d - %d == %d\n", PointerOfTextSection, PaddingDistance, PaddingSize);

	BYTE *PaddingByte = (BYTE*)malloc(PaddingSize);
	memset(PaddingByte, 0, PaddingSize);

	FILE *fp = fopen("out.exe", "wb");
	if(fp == NULL)
	{
		printf("error: cannot open file\n");
		free(PaddingByte);
		return 0;
	}
	
	fwrite(&DosHeader, sizeof(DosHeader), 1, fp);
	fwrite(&NtHeaders32, sizeof(NtHeaders32), 1, fp);
	fwrite(&SectionHeader, sizeof(SectionHeader), 1, fp);
	fwrite(PaddingByte, 1, PaddingSize, fp);
	fwrite(SHELLCODE, sizeof(SHELLCODE), 1, fp);
	fclose(fp);

	free(PaddingByte);

    return 0;
}