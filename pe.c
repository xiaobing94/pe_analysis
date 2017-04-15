#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pe.h"


/*判断是否是PE文件, 不断完善， 暂时用MZ来校验*/
BOOLEAN isPE(DosHeader * dosheader, NtHeader * ntheader)
{
	if (dosheader->signtrue == IMAGE_DOS_SIGNATURE
		&& ntheader->signature == IMAGE_NT_SIGNATURE) //MZ 高低，和文件内容相反
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}

}

/*
获取PE头的文件偏移量
*/
int getNtHeaderoffset(DosHeader *dosheader) {
	return dosheader->e_lfanew;
}

/*获取rva所在节*/
ImageSectionHeader* getSectionHeaderByRva(int rva, ImageSectionHeader *imageSectionHeader, int len)
{
	int i = 0;
	for (i = 1; i <= len; i++)
	{
		if (!imageSectionHeader)
		{
			return NULL;
		}
        if (imageSectionHeader->virtualAddress <= rva && 
                rva < imageSectionHeader->virtualAddress + imageSectionHeader->misc.virtualSize){
            return imageSectionHeader;
        }
        imageSectionHeader = imageSectionHeader + 1;
	}
    return NULL;
}


void printImageFileHeaderInfo(NtHeader *ntHeader)
{
	ImageFileHeader * imageFileHeader;
	imageFileHeader = &(ntHeader->imageFileHeader);
	printf("\n");
	printf("PE文件头信息：\n");
	printf("所需CPU:0x%04x\n", imageFileHeader->machine);
	printf("块数目:0x%04x\n", imageFileHeader->numberOfSections);
	printf("编译时间:0x%04x\n", imageFileHeader->timeDateStamp);
	printf("可选头大小0x%04x\n", imageFileHeader->sizeOfOptionalHeader);
	printf("文件信息标志:0x%04x\n", imageFileHeader->characteristics);
}

/*获取节rva*/
/*int getAdjustSectionAlignment(NtHeader *ntHeader, int virtualAddress)
{
    ImageOptionalHeader32 * optionalHeader = &(ntHeader->imageOptionalHeader32);
    int sectionAlignment = optionalHeader->sectionAlignment;
    int fileAlignment = optionalHeader->fileAlignment;
    if (sectionAlignment < 0x1000)
    {
        sectionAlignment = fileAlignment;
    }
    if (virtualAddress && virtualAddress % sectionAlignment)
    {
        return sectionAlignment * ( virtualAddress / sectionAlignment);
    }
    return virtualAddress;
}*/

/*获取节在文件中的偏移量*/
/*int getAdjustFileAlignment(NtHeader *ntHeader, int pointerToRawData)
{
    ImageOptionalHeader32 * optionalHeader = &(ntHeader->imageOptionalHeader32);
    int fileAlignment = optionalHeader->fileAlignment;
    if (fileAlignment < 0x200)
    {
        return pointerToRawData;
    }
    return (pointerToRawData/fileAlignment)*0x200;
}*/

/*rva获取段内便宜*/
int rva2fileoffset(int rva, ImageSectionHeader *sectionHeader, int sectionLen)
{
    ImageSectionHeader* tmpSectionHeader = getSectionHeaderByRva(rva, sectionHeader, sectionLen);
	if (!tmpSectionHeader)
	{
		return NULL;
	}
	return (tmpSectionHeader->pointerToRawData + (rva - tmpSectionHeader->virtualAddress));
}

/*rva获取段偏移*/
int rva2SectionOffset(int rva, ImageSectionHeader *sectionHeader, int sectionLen)
{
	ImageSectionHeader* tmpSectionHeader = getSectionHeaderByRva(rva, sectionHeader, sectionLen);
	if (!tmpSectionHeader)
	{
		return NULL;
	}
	return tmpSectionHeader->pointerToRawData;
}
/*
获取有多少个节表
*/
int getNumberOfSections(NtHeader *ntHeader)
{
	ImageFileHeader * imageFileHeader;
	imageFileHeader = &(ntHeader->imageFileHeader);
	return imageFileHeader->numberOfSections;
}

void printNtHeaderInfo(NtHeader *ntHeader)
{
	ImageOptionalHeader32 * optionalHeader;
	optionalHeader = &(ntHeader->imageOptionalHeader32);
	printf("\n");
	printf("可选头信息：\n");
	printf("程序执行入口:0x%08x\n", optionalHeader->addressOfEntryPoint);
	printf("代码节的起始:0x%08x\n", optionalHeader->baseOfCode);
	printf("数据节的起始rva:0x%08x\n", optionalHeader->baseOfData);
	printf("程序的优先装载地址imagebase:0x%08x\n", optionalHeader->imageBase);
	printf("初始化时保留的栈的大小:0x%08x\n", optionalHeader->sizeOfStackReserve);
	printf("初始化时保留的堆的大小:0x%08x\n", optionalHeader->sizeOfHeapReserve);
}

/*在文件中的偏移量*/
int getPointerToRawData(ImageSectionHeader *imageSectionHeader)
{
	return imageSectionHeader->pointerToRawData;
}

/*输出节信息*/
void printSectionInfo(ImageSectionHeader *imageSectionHeader, int len)
{
	int i = 0;
	printf("\n");
	printf("节表信息：\n");
	for (i = 1; i <= len; i++)
	{
		printf("第%d节信息:\n", i);
		printf("节名:%s\n", imageSectionHeader->name);
		printf("节区的物理地址或真实长度:0x%08x\n", imageSectionHeader->misc.physicalAddress);
		printf("节区的 RVA 地址:0x%08x\n", imageSectionHeader->virtualAddress);
		printf("在文件中的偏移量:0x%08x\n", imageSectionHeader->pointerToRawData);
		printf("节属性:0x%08x\n", imageSectionHeader->characteristics);
		printf("\n");
		imageSectionHeader = imageSectionHeader + 1;
	}
}

/*打印导入表信息*/
void printImportSectionInfo(char * data, ImageImportDirectory *imageImportDirectory, ImageSectionHeader * sectionHeaders, int size, int numberOfSections)
{
	int i = 0;
	printf("size:%d", size);
	int len = size / sizeof(ImageImportDirectory);
	int offset = 0;
	printf("len:%d\n", len);
	printf("导入表信息：\n");
	for (i = 0; i < len; i++)
	{
		if (!imageImportDirectory->name)
		{
			return ;
		}
		offset = rva2fileoffset(imageImportDirectory->name, sectionHeaders, numberOfSections);
		if (!offset)
		{
			break;
		}
		printf("导入名称:%s\n", data + offset);
		//printf("导入名称:%s\n", imageImportDirectory->name);
		printf("时间戳:0x%08x\n", imageImportDirectory->timeDateStamp);
		//printf("Data数组的rva值:0x%08x\n", imageImportDirectory->dummy.importThunk);
		printf("Data数组的rva值:0x%08x\n", imageImportDirectory->firstThunk);
		printf("正向链接索引:0x%08x\n", imageImportDirectory->forwarderChain);
		printf("\n");
		imageImportDirectory = imageImportDirectory + 1;
	}
}

/*获取IAT的rva*/
ImageThunkData32 * getIATrva(char *data, ImageImportDirectory *imageImportDirectory, ImageSectionHeader * sectionHeader, int sectionLen)
{
	ImageThunkData32 *imageThunkData32 = NULL;
	//printf("0x%x,0x%x,", imageImportDirectory->dummy.originalFirstThunk, imageImportDirectory->firstThunk);
	imageThunkData32 = (ImageThunkData32 *)(data + rva2fileoffset(imageImportDirectory->dummy.originalFirstThunk, sectionHeader, sectionLen));
	return imageThunkData32;
}

/*输出IAT信息*/
void printIATInfo(char *data, ImageThunkData32 * imageThunkData32, ImageSectionHeader * sectionHeader, int sectionLen)
{
	int offset = 0;
	ImageImportByName *imageImportByName = NULL;
	while (imageThunkData32->u1.addressOfData)
	{
		int offset = rva2fileoffset(imageThunkData32->u1.addressOfData, sectionHeader, sectionLen);
		imageImportByName = (ImageImportByName *)(data + offset);
		printf("函数名:%s\n", imageImportByName->name);
		imageThunkData32 = imageThunkData32 + 1;
	}
}

/*输出所有的导入函数信息*/
void printImportInfo(char *data, ImageImportDirectory *imageImportDirectory, ImageSectionHeader * sectionHeader, int sectionLen)
{
	ImageThunkData32 *imageThunkData32 = getIATrva(data, imageImportDirectory, sectionHeader, sectionLen);
	printf("\n导入函数列表:\n");
	printIATInfo(data, imageThunkData32, sectionHeader, sectionLen);
}

/*导出函数列表*/
void printExportFunctionInfo(char * data, ImageExportDirectory *imageExportDirectory, ImageSectionHeader * sectionHeaders, ImageSectionHeader * headerSectionHeaders,int numberOfSections)
{
	int i = 0;
	int offset = 0;
	int *nameAddr = NULL;
	int *funcAddr = NULL;
	if (imageExportDirectory->name == NULL)
	{
		return;
	}
	offset = rva2fileoffset(imageExportDirectory->name, sectionHeaders, numberOfSections);
	if (!offset)
	{
		return;
	}
	funcAddr = imageExportDirectory->addressOfFunctions;
	for (i = 1; i <= imageExportDirectory->numberOfFunctions; i++)
	{
		printf("函数序号%d：rva:0x%08x\n", i, funcAddr);
		int offset = rva2fileoffset(funcAddr, sectionHeaders, numberOfSections);
		int *func_rva = (int *)(data + offset);
		int rav_offset = rva2fileoffset(*func_rva, headerSectionHeaders, numberOfSections);
		//int section_offse = rva2SectionOffset(*func_rva, headerSectionHeaders, numberOfSections);
		printf("函数偏移量:0x%08x\n", rav_offset);
		printf("函数%d文件偏移量：0x%08x\n", i, offset);
		funcAddr = funcAddr + 1;
	}
	nameAddr = (int *)(data + rva2fileoffset(imageExportDirectory->addressOfNames, sectionHeaders, numberOfSections));
	for (i = 0; i < imageExportDirectory->numberOfNames; i++)
	{
		char *name = (data + rva2fileoffset((*nameAddr), sectionHeaders, numberOfSections));
		printf("函数名：%s\n", name);
		nameAddr = nameAddr + 1;
	}
	printf("\n");
}

/*打印导出表信息*/
void printExportSectionInfo(char * data, ImageExportDirectory *imageExportDirectory, ImageSectionHeader * sectionHeaders, ImageSectionHeader * headerSectionHeaders, int size, int numberOfSections)
{
	int i = 0;
	printf("size:%d", size);
	int len = size / sizeof(ImageExportDirectory);
	int offset = 0;
	printf("len:%d\n", len);
	printf("导出表信息：\n");
	for (i = 0; i < len; i++)
	{
		if (imageExportDirectory->name == NULL)
		{
			break;
		}
		offset = rva2fileoffset(imageExportDirectory->name, sectionHeaders, numberOfSections);
		if (!offset)
		{
			break;
		}
		printf("导出名称:%s\n", data + offset);
		printf("时间戳:0x%08x\n", imageExportDirectory->timeDateStamp);
		printf("函数的数量:0x%08x\n", imageExportDirectory->numberOfFunctions);
		printf("按名字导出函数的数量:0x%08x\n", imageExportDirectory->numberOfNames);
		printf("导出函数的文件偏移量:0x%08x\n", imageExportDirectory->addressOfFunctions);
		printf("按名字导出函数的文件偏移量:0x%08x\n", imageExportDirectory->addressOfNames);
		printExportFunctionInfo(data, imageExportDirectory, sectionHeaders, headerSectionHeaders, numberOfSections);
		printf("导入函数序号的文件偏移量（数组):0x%08x\n", imageExportDirectory->addressOfNameOrdinals);
		printf("\n");
		imageExportDirectory = imageExportDirectory + 1;
	}
}

/*打印每一行*/
void printline(char * hex, int len)
{
	int i = 0;
	if (len == 0 || hex == NULL || len > 0x10)
		return;
	for (i = 0; i < len; i++)
	{
		// 打印每个字节
		printf("%02x ", *(hex + i));
	}
	printf("\n");	//每行打印完回车
}


/*打印*/
// 打印一段内存的二进制
void printhex(char * hex, int len)
{
	int i;
	int lastnum = len & 0xF;	//计算最后一行有多少个字节，如果刚好是整数则为0
	int line = len >> 4;		//计算有多少行，不算最后一行不饱满情况
	for (i = 0; i < line; i++)
	{
		// 打印每一行，每行16个字节
		printline(hex + i * 0x10, 0x10);
	}
	if (lastnum)
	{
		// 最后一行不满16字节
		if (line) {

			printline(hex + lastnum * 0x10, lastnum);
		}
		else {  // 如果只有一行
			printline(hex, lastnum);
		}
	}

}

/*获取文件长度*/
int getFileLen(FILE *fp)
{
	int filesize = 0;
	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	return filesize;
}

/*将布尔转换为是否*/
char * boolean2string(int bool)
{
	if (bool)
	{
		return "是";
	}
	else
	{
		return "否";
	}

}
/*获取所有的数据 修改了 不使用fgets，使用fread*/
char* getFileData(FILE *fp, char *str, int filesize)
{
	size_t len;
	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	memset(str, 0, filesize + 1);
	rewind(fp);
	len = fread(str, 1, filesize, fp);

	if (len != filesize)
	{
		return NULL;
	}

	return str;
}

/*主函数*/
void main(int argc, char **argv)
{
	// 1.读取文件
	// 2.解析dos头
	// 3.解析option header
	// 4.解析section table
	char * file_name = argv[1];
	FILE *fp = NULL;
	DosHeader *dosHeader = NULL; //dos头
	NtHeader *ntHeader = NULL;  // nt头
	//ImageDataDirectory *dataDirectory = NULL;
	ImageSectionHeader *imageSectionHeader = NULL;
    ImageSectionHeader *importSectionHeader = NULL;
    ImageSectionHeader *exportSectionHeader = NULL;
	ImageDataDirectory *importDataDirectory = NULL;
	ImageDataDirectory *exportDataDirectory = NULL;
	ImageImportDirectory *imageImportDirectory = NULL;
	ImageExportDirectory *imageExportDirectory = NULL;
	int numberOfSections = 0;
	int filesize = 0;  //文件大小
	int ntoffset = 0;  //nt头的便宜量
	char *data = NULL;  //用于指向数据
	// 读取内容
	if (!file_name)
	{
		printf("请传入参数文件名");
		goto end;
	}
	if ((fp = fopen(file_name, "rb")) == NULL)
	{
		printf("不能打开文件");
		exit(1);
	}
	filesize = getFileLen(fp);
	data = (char *)malloc(filesize + 1);
	if (data == NULL)
	{
		printf("分配内存失败");
		goto end;
	}
	getFileData(fp, data, filesize);
	// 解析dosheader
	dosHeader = (DosHeader *)data;
	ntoffset = getNtHeaderoffset(dosHeader);
	// printf("PE头位置:0x%02x\n", getNtHeaderoffset(dosheader));
	// nt头信息
	ntHeader = (NtHeader *)(data + ntoffset);
	printImageFileHeaderInfo(ntHeader);
	printNtHeaderInfo(ntHeader);
	exportDataDirectory = &(ntHeader->imageOptionalHeader32.dataDirectory[0]); // 导出表信息
	importDataDirectory = &(ntHeader->imageOptionalHeader32.dataDirectory[1]); // 导入表信息

	imageSectionHeader = (ImageSectionHeader *)(data + ntoffset + sizeof(NtHeader));
	printSectionInfo(imageSectionHeader, getNumberOfSections(ntHeader));
	numberOfSections = getNumberOfSections(ntHeader);
    exportSectionHeader = getSectionHeaderByRva(exportDataDirectory->virtualAddress, imageSectionHeader, numberOfSections); // 导出表所在节
	importSectionHeader = getSectionHeaderByRva(importDataDirectory->virtualAddress, imageSectionHeader, numberOfSections); // 导出表所在节
	imageExportDirectory = (ImageExportDirectory *)(data + rva2fileoffset(exportDataDirectory->virtualAddress, exportSectionHeader, numberOfSections));
	imageImportDirectory = (ImageImportDirectory *)(data + rva2fileoffset(importDataDirectory->virtualAddress, importSectionHeader, numberOfSections));
	printExportSectionInfo(data, imageExportDirectory, exportSectionHeader, imageSectionHeader, exportDataDirectory->size, numberOfSections);
	printImportSectionInfo(data, imageImportDirectory, importSectionHeader, importDataDirectory->size, numberOfSections);

	//rva2fileoffset(*func_rva, imageSectionHeader, numberOfSections)
	printImportInfo(data, imageImportDirectory, imageSectionHeader, numberOfSections);
	getchar();
end:
	if (data != NULL)
	{
		free(data);
	}
	if (fp != NULL)
	{
		fclose(fp);
	}
}
