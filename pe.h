//#define NULL 0
#define BUF_SIZE 0x100
#define BYTE char
#define WORD short
#define DWORD int
#define BOOLEAN int
#define TRUE 1
#define FALSE 0
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE  0x00004550

typedef struct _DOS_HEADER {
	WORD signtrue;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	DWORD e_lfanew;
} DosHeader;

typedef struct _IMAGE_FILE_HEADER {
	WORD    machine; // 运行平台
	WORD    numberOfSections; // 文件的区块数目
	DWORD   timeDateStamp; // 文件创建日期和时间  
	DWORD   pointerToSymbolTable;  // 指向符号表(主要用于调试)
	DWORD   numberOfSymbols;  // 符号表中符号个数(同上)  
	WORD    sizeOfOptionalHeader;   // IMAGE_OPTIONAL_HEADER32 结构大小  
	WORD    characteristics;  // 文件属性 
} ImageFileHeader, *PImageFileHeader;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   virtualAddress; //数据的起始RVA
	DWORD   size;  //数据块的长度
} ImageDataDirectory, *PImageDataDirectory;

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD    magic;  // 10B 32位PE 20B 64位PE 107 ROM映像
	BYTE    majorLinkerVersion;  // 链接器版本号
	BYTE    minorLinkerVersion;  // 链接器副版本号
	DWORD   sizeOfCode;  // 所有代码节的总和  该大小是基于文件对齐后的大小
	DWORD   sizeOfInitializedData;  // 所有含已初始化数据的节的总大小
	DWORD   sizeOfUninitializedData;  // 所有含未初始化数据的节的大小
	DWORD   addressOfEntryPoint;  // 程序执行入口RVA
	DWORD   baseOfCode;  // 代码节的起始RVA
	DWORD   baseOfData;  // 数据节的起始RVA
	DWORD   imageBase;  // 程序的优先装载地址
	DWORD   sectionAlignment; // 内存中节的对齐粒度
	DWORD   fileAlignment;  // 文件中节的对齐粒度
	WORD    majorOperatingSystemVersion; // 操作系统主版本号
	WORD    minorOperatingSystemVersion;  // 操作系统副版本号
	WORD    majorImageVersion;  // PE文件映像的版本号
	WORD    minorImageVersion;
	WORD    majorSubsystemVersion;  // 子系统的版本号
	WORD    minorSubsystemVersion;
	DWORD   win32VersionValue;  // 未用 必须设置0
	DWORD   sizeOfImage;  // 内存中整个PE文件的映像尺寸
	DWORD   sizeOfHeaders; // 所有节表按照文件对齐粒度后的大小
	DWORD   checkSum; // 校验和
	WORD    subsystem; // 指定使用界面的子系统
	WORD    dllCharacteristics; // DLL文件属性
	DWORD   sizeOfStackReserve; // 初始化时保留的栈的大小
	DWORD   sizeOfStackCommit; // 初始化时实际提交的栈的大小
	DWORD   sizeOfHeapReserve; // 初始化时保留的堆的大小
	DWORD   sizeOfHeapCommit; // 初始化时实际提交的堆的大小
	DWORD   loaderFlags; // 加载标志  未用
	DWORD   numberOfRvaAndSizes; // 下面的数据目录结构的数量
	ImageDataDirectory dataDirectory[16];
} ImageOptionalHeader32, *PImageOptionalHeader32;

typedef struct _NT_HEADER
{
	DWORD signature;
	ImageFileHeader imageFileHeader;
	ImageOptionalHeader32 imageOptionalHeader32;
} NtHeader, *PNtHeader;

typedef struct _IMAGE_SECTION_HEADER
{
	BYTE name[IMAGE_SIZEOF_SHORT_NAME];
	union
	{
		DWORD physicalAddress; //物理地址
		DWORD virtualSize; //真实长度
	} misc;
	DWORD virtualAddress; // 节区的 RVA 地址
	DWORD sizeOfRawData; // 在文件中对齐后的尺寸
	DWORD pointerToRawData; // 在文件中的偏移量
	DWORD pointerToRelocations; // 在OBJ文件中使用，重定位的偏移
	DWORD pointerToLinenumbers; // 行号表的偏移（供调试使用地）
	WORD numberOfRelocations; // 在OBJ文件中使用，重定位项数目
	WORD numberOfLinenumbers; // 行号表中行号的数目
	DWORD characteristics; // 节属性如可读，可写，可执行等
} ImageSectionHeader, *PImageSectionHeader;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   characteristics;
	DWORD   timeDateStamp;
	WORD    majorVersion;
	WORD    minorVersion;
	DWORD   name;
	DWORD   base;
	DWORD   numberOfFunctions;
	DWORD   numberOfNames;
	DWORD   addressOfFunctions;
	DWORD   addressOfNames;
	DWORD   addressOfNameOrdinals;
} ImageExportDirectory, *PImageExportDirectory;

typedef struct _IMAGE_IMPORT_DIRECTORY {
	union {
		DWORD   importThunk;
		DWORD   originalFirstThunk;
	} dummy;
	DWORD   timeDateStamp;
	DWORD   forwarderChain;
	DWORD   name;   //名称
	DWORD   firstThunk;
} ImageImportDirectory, *PImageImportDirectory;


typedef struct _IMAGE_THUNK_DATA32 {
	union {
		DWORD forwarderString;      // PBYTE
		DWORD function;             // PDWORD
		DWORD ordinal;
		DWORD addressOfData;        // PIMAGE_IMPORT_BY_NAME
	} u1;
} ImageThunkData32, *PImageThunkData32;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD    hint;
	BYTE    name[1];
} ImageImportByName, *PimageImportByName;

/*
typedef struct _PE
{
DosHeader dosHeader;
NtHeader ntHeader;
} PE,  *PPE;
*/
