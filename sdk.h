/*
	Considerations before using the header:

	1.-This SDK header contains most of the fully rebuild and half-rebuilded typedefs that I used in my ResetEngine.dll IDB 
	just for my particular goal (Achieving code execution).
	Because of this, some of them are not completely accurate in terms of labels (specially the void* members), 
	You can modify and update them in your LOCAL TYPES as you see fit.
	
	2.-A lot of the objects used here use some sort of object manager (just like smart pointers) to obtain one pointer to an object.
	This was emulated using the structure RaiiAutoPbrDelete inside this header. 
	Use it as needed, and change the return value of the particular methods inside it to fit your neccesities.
	
	3.-Containers that heavily use templates (mainly the ATL containers), were emulated just as seen in the resource below:
	https://www.msreverseengineering.com/blog/2021/9/21/automation-in-reverse-engineering-c-template-code
	It is recommended you create one different type for IDA per particular template specialization.
	
	4.-To know where to apply each of the different types defined here, focus on the symbols applied by IDA after downloading the MS pdb.
*/
#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

struct Property;
struct Session;
struct CString;
struct CAtlArray;
struct _GUID;
struct BoolProperty;
struct OperationQueue;
struct VtableOperationObj;
struct BaseOperation;
struct CAtlStringMgr;
struct CAtlStringMgrVtable;
struct CWin32Heap;
struct CAtlPlex;
struct CStringData;
struct OnlineKey;
struct OnlineKeyVtable;
struct WorkingDirs;
struct SystemInfo;
struct ExecState;
struct CNodeRunCommand;

typedef struct _GUID GUID;

struct _GUID
{
  unsigned int Data1;
  unsigned __int16 Data2;
  unsigned __int16 Data3;
  unsigned __int8 Data4[8];
};

typedef unsigned int ULONG;
typedef unsigned int UINT32;
typedef unsigned __int16 UINT16;
typedef unsigned __int8 UINT8;
typedef unsigned __int64 UINT64;
typedef unsigned __int16 USHORT;
typedef unsigned __int8 UCHAR;
typedef unsigned __int64 ULONGLONG;
typedef int LONG;
typedef unsigned __int64 ULONG_PTR;
typedef unsigned __int16 WORD;
typedef unsigned int DWORD;
typedef unsigned __int16 wchar_t;
typedef wchar_t WCHAR;
typedef WCHAR *PWSTR;
typedef int BOOL;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef void *LPVOID;
typedef void *PVOID;
typedef unsigned __int64 size_t;
typedef char CHAR;
typedef unsigned __int8 BYTE;

struct OnlineKey
{
  OnlineKeyVtable *vtableOnlineKey;
  void *hKey;
};

struct OnlineKeyVtable
{
  void *DestructorOnlineKey;
  void *GetSecurityOnlineKey;
  void *SetSecurityOnlineKey;
  void *OpenSubkeyOnlineKey;
  void *CreateSubkeyOnlineKey;
  void *DeleteSubtreeOnlineKey;
  void *EnumSubkeysOnlineKey;
  void *HasValueRegKey;
  void *HasValueOnlineKey;
  void *GetValueRegKey1;
  void *GetValueRegKey2;
  void *GetValueRegKey3;
  void *GetValueOnlineKey;
  void *SetValueRegKey;
  void *SetValueOnlineKey;
  void *DeleteValueRegKey;
  void *DeleteValueOnlineKey;
  void *EnumValuesRegKey;
  void *EnumValuesOnlineKey;
  void *CopyToRegKey;
};

struct CAtlArray
{
  void **m_pData_type;
  size_t m_nSize;
  size_t m_nMaxSize;
  int m_nGrowBy;
};

struct Property
{
  void *vtableProperty;
  CAtlArray *arrayProperty;
  wchar_t *propertyString;
};

struct BoolProperty
{
  Property propertyObj;
  bool bCheck;
};

struct CString
{
  wchar_t **__shifted(CStringData,0x18) m_pchData;
};

struct Session
{
  CAtlArray m_arrayProperties;
  BoolProperty m_ConstructCheck;
  BoolProperty m_ReadyCheck;
  WorkingDirs *m_WorkingDirsPtr;
  void *m_TelemetrySessionPtr;
  void *m_OfflineBootPtr;
  void *m_DebugObjectPtr;
  void *m_CloudConnectionPtr;
  void *m_CloudImgPtr;
  void *m_PtrToSomeObject; 
  void *m_PayloadConnectionPtr;
  void *m_PayloadInfoPtr;
  CString m_TargetVolumeDriveLetter;
  void *m_OptionsPtr;
  SystemInfo *m_SystemInfoPtr;
  DWORD IndexExecPhaseOption;
  BYTE gap_bytes[4];
  ExecState *ExecStatePtr;
  OperationQueue *OperationQueueObjOfflineOperations;
  OperationQueue *OperationQueueObjOnlineOperations;
  void* TriggerCommand1;
  void* TriggerCommand2;
  void* TriggerCommand3;
};

struct WorkingDirs
{
  __int64 m_SysResetFolder;
  __int64 m_LogSubdirectory;
  __int64 m_ScratchSubdirectory;
  __int64 m_MdmFolder;
  __int64 m_OldOsFolder;
  __int64 m_CloudImageDir;
};

#pragma pack(push, 8)
struct CStringData
{
  CAtlStringMgr *pStringManager;
  int nDataLength;
  int nAllocLength;
  int nRefs;
};
#pragma pack(pop)

struct __cppobj IntProperty : Property
{
  DWORD m_int_for_property;
};

struct __cppobj StringProperty : Property
{
  CString *CStringMember;
};

struct __cppobj PathProperty : Property
{
  CString CStringPath;
};

struct __cppobj CharProperty : Property
{
  wchar_t m_char_member;
};

struct __cppobj GuidProperty : Property
{
  __declspec(align(4)) GUID m_guid;
};

struct __cppobj PathListProperty : Property
{
  CAtlArray m_ArrPathList;
};

/* 529 */
struct __cppobj UInt64Property : Property
{
  __int64 m_int64_member;
};

struct __cppobj StringListProperty : Property
{
  CAtlArray StringListProperties;
};

struct SystemInfo
{
  CAtlArray arrProperties;
  BoolProperty m_PowerSourceIsUnreliable;
  IntProperty m_HostVersionMajor;
  IntProperty m_HostVersionMinor;
  IntProperty m_HostBuild;
  StringProperty m_BootLocale;
  IntProperty m_BootTimeout;
  PathProperty m_BootVolume;
  CharProperty m_BootDrive;
  BoolProperty m_SecureBootEnabled;
  BoolProperty m_IsTeamOs;
  BoolProperty m_IsWindowsToGo;
  BoolProperty m_IsSafeMode;
  BoolProperty m_IsWindowsPE;
  StringProperty m_RamDiskDevice;
  PathProperty m_RamdiskVolumeRoot;
  PathProperty m_RamdiskPath;
  BoolProperty m_WinREAvailable;
  PathProperty m_WinREVolumeRoot;
  PathProperty m_WinREPath;
  GuidProperty m_WinREBootEntry;
  IntProperty m_WinREVersionMajor;
  IntProperty m_WinREVersionMinor;
  IntProperty m_WinREBuild;
  BoolProperty m_StagedWinREAvailable;
  PathProperty m_StagedWinREPath;
  BoolProperty m_ArchivedWinREAvailable;
  PathProperty m_ArchivedWinREPath;
  BoolProperty m_DownlevelWinREAvailable;
  PathProperty m_DownlevelWinREVolumeRoot;
  PathProperty m_DownlevelWinREPath;
  IntProperty m_DownlevelWinREVersionMajor;
  IntProperty m_DownlevelWinREVersionMinor;
  IntProperty m_DownlevelWinREBuild;
  BoolProperty m_RecoveryImageAvailable;
  PathProperty m_RecoveryImageVolumeRoot;
  PathProperty m_RecoveryImagePath;
  IntProperty m_RecoveryImageIndex;
  PathListProperty m_RecoveryImageReferencePaths;
  IntProperty m_RecoveryImageVersionMajor;
  IntProperty m_RecoveryImageVersionMinor;
  IntProperty m_RecoveryImageBuild;
  StringProperty m_RecoveryImageEdition;
  IntProperty m_RecoveryImageArchitecture;
  PathProperty m_RecoveryImageOEMResetConfigPath;
  BoolProperty m_TargetAccessible;
  BoolProperty m_TargetInstallHealthy;
  UInt64Property m_TargetVolumeCapacity;
  UInt64Property m_TargetSpaceRemaining;
  BoolProperty m_TargetEncrypted;
  BoolProperty m_TargetEncryptionSuspended;
  BoolProperty m_TargetLocked;
  IntProperty m_TargetVersionMajor;
  IntProperty m_TargetVersionMinor;
  IntProperty m_TargetBuild;
  IntProperty m_TargetRevision;
  StringProperty m_TargetBuildBranch;
  StringProperty m_TargetCurrentBuild;
  StringProperty m_TargetBuildLab;
  StringProperty m_TargetProductName;
  StringProperty m_TargetEdition;
  IntProperty m_TargetArchitecture;
  IntProperty m_TargetInstallType;
  BoolProperty m_TargetHasRedirectedProfiles;
  BoolProperty m_TargetCompact;
  BoolProperty m_TargetIsSignature;
  BoolProperty m_TargetRunsNarratorOnLogon;
  BoolProperty m_PolicyDisablesReset;
  BoolProperty m_PolicyDisablesCustomizations;
  BoolProperty m_PolicyDisablesDriverMigration;
  BoolProperty m_PolicyDisablesReconstructToLatest;
  PathListProperty m_TargetHydratedProvPackages;
  PathListProperty m_TargetDehydratedProvPackages;
  PathProperty m_TargetProvPackageInstallOrder;
  StringListProperty m_TargetRuntimeProvPackages;
  PathProperty m_TargetOEMResetConfigPath;
  PathProperty m_TargetOEMAutoApplyPath;
  PathProperty m_RamdiskMigrationXML;
  PathProperty m_TargetMigrationXML;
  PathProperty m_TargetReprovisionMigrationXML;
  BoolProperty m_IsRecoveryMediaBoot;
  PathProperty m_MediaRoot;
  PathProperty m_MediaImageRoot;
  PathProperty m_MediaProvPackageRoot;
  PathProperty m_MediaExtensibilityRoot;
  PathProperty m_MediaAutoApplyRoot;
  PathProperty m_MediaBootWimPath;
  PathProperty m_MediaWinREPath;
  PathProperty m_MediaDownlevelWinREPath;
  PathProperty m_MediaOEMResetConfigPath;
  PathProperty m_MediaAutoResetConfigPath;
  PathListProperty m_MediaRecoveryImageNames;
  PathListProperty m_MediaComponentStoreImagePaths;
  StringListProperty m_MediaProvPackageNames;
  PathProperty m_MediaProvPackageInstallOrder;
  StringListProperty m_MediaSingleInstancedProvPackages;
  BoolProperty m_NarratorRunning;
  GuidProperty m_SystemDefaultEntry;
};

struct ExecState
{
  CAtlArray arrProperties;
  BoolProperty m_HaveTargetVolume;
  BoolProperty m_TargetVolumeAccessible;
  PathProperty m_TargetVolumeRoot;
  UInt64Property m_TargetVolumeCapacity;
  UInt64Property m_TargetVolumeFreeSpace;
  BoolProperty m_HaveOldOS;
  PathProperty m_OldOSRoot;
  BoolProperty m_HaveNewOS;
  PathProperty m_NewOSRoot;
  GuidProperty m_NewOSBootEntry;
  BoolProperty m_SetupSourcesCleaned;
  PathProperty m_SetupSourcesDir;
  BoolProperty m_SavedWinRE;
  BoolProperty m_IgoreDiskSpaceValidate;
  DWORD dwValueRemediation;
};

struct OperationQueue
{
  BaseOperation **OperationsToDo;
  __int64 sizeOperations;
  __int64 MaxCountOperations;
  int member_not_used;
  int gap_bytes;
};

/* 545 */
struct __cppobj CNilStringData : CStringData
{
  wchar_t achNill[2];
};

/* 483 */
struct CAtlStringMgr
{
  CAtlStringMgrVtable *vt_StrMgr;
  CWin32Heap *m_pMemMgr;
  CNilStringData m_nill;
};

/* 467 */
struct BaseOperation
{
  VtableOperationObj *VtableOperation;
  CAtlArray m_ArrayProperties;
  CString m_OperationName;
  BoolProperty m_ExecutedProperty;
  void *m_SessionObj;
  void *m_TelemetryObjPtr;
};

/* 484 */
struct CAtlStringMgrVtable
{
  void *AllocateString;
  void *FreeString;
  void *ReAllocateString;
  void *GetNilString;
  void *CloneAtlStringMgr;
  void *AtlDestructorVtable;
};

/* 485 */
struct CWin32Heap
{
  void *Allocate;
  void *Free;
  void *Reallocate;
  void *GetSize;
  void *VtableDestructor;
};

/* 466 */
struct VtableOperationObj
{
  void* InternalSave;
  void* InternalLoad;
  void* InternalValidate;
  void* InternalComputeWeight;
  void* InternalEstimateDiskUsage;
  void* InternalExecute;
  void* InternalApply;
  void* ReturnErrorCodeFile;
  void* DestroyInstace;
  void* GetDescription;
};

/* 468 */
struct ExecuteProgressObj
{
  __int64 VtableExecuteProgres;
  __int64 CabFileObjPtr;
};

/* 469 */
struct ScenarioEntry
{
  __int64 idScenario;
  void *ScenarioCreateFunction;
};

/* 470 */
struct ScenarioArray
{
  ScenarioEntry entries[10];
};

/* 471 */
struct ScenarioVirtualFunctions
{
  void *GetType;
  void *InternalCheckSupport;
  void *InternalConstruct;
  void *InternalCheckDiskSpace;
  void *CheckMediaSupported;
  void *ConstructMedia;
  void *GetRestoredApps;
  void *GetEncryptionSettings;
  void *RequiresBootLockDown;
};

/* 472 */
struct Scenario
{
  ScenarioVirtualFunctions *vTableScenario;
  void *m_ScratchSubDir;
  void *m_MdmFolder;
  void *m_TargetVolume;
};

/* 477 */
struct __cppobj DerivedScenarioType1 : Scenario
{
  void *m_TelemetryObjptr;
  void *m_ScenarioTypeObjPtr;
  void *m_CloudImgObjPtr;
  void *m_PayloadInfoPtr;
  void *m_OptionsObjPtr;
  SystemInfo *m_SystemInfoPtr;
};

/* 478 */
struct CleanUpBase
{
  void *GetObjectReference;
  void *GetObjectPtr1;
  void *GetObjectPtr2;
  void *GetObjectPtr3;
  void *GetObjectPtr4;
  void *DestructObject;
  void *CheckPointerEqual;
  void *CheckPointerNotEqual;
  void *CheckPointerIsNull;
  void *GetAndDestroyPtr;
  void *DestroyPtr;
  void *FreeBufferPointer;
  void *Destructor;
};

/* 479 */
struct RaiiAutoPbrDelete
{
  void *GetObjectPtrAddingOffset;
  CleanUpBase cleanUpInterface;
};

typedef BYTE *LPBYTE;

/* 487 */
struct __cppobj OpRunExtension : BaseOperation
{
  BoolProperty m_IsRequired;
  StringProperty m_PhaseExecution;
  PathProperty m_ExtensibilityDir;
  StringProperty m_CommandPath;
  StringProperty m_Arguments;
  IntProperty m_Duration;
  IntProperty m_Timeout;
  PathProperty m_RecoveryImageLocation;
  BoolProperty m_WipeDataCheck;
  BoolProperty m_PartitionDiskCheck;
};

/* 495 */
struct boolChecks
{
  bool RecoveryFolders;
  bool UserFoldersConfigs;
};

/* 494 */
union __declspec(align(2)) InternalChecks
{
  uint16_t initBools;
  boolChecks UnionChecks;
};

/* 493 */
struct Options
{
  void *AtlStringMember1;
  void *AtlStringMember2;
  void *AtlStringMember3;
  InternalChecks InternalChecks;
  bool checkSet;
};

/* 513 */
struct OperationMetadata
{
  wchar_t *StringIdOperation;
  void *PtrFunctionConstruct;
};

/* 512 */
struct CPairMapOpMetadata
{
  CString *m_key;
  OperationMetadata m_value;
};

/* 497 */
#pragma pack(push, 8)
struct __cppobj CNodeMapOpMetadata : CPairMapOpMetadata
{
  CNodeMapOpMetadata *m_pNext;
  UINT m_nHash;
};
#pragma pack(pop)

/* 498 */
struct CAtlMapOpMetadata
{
  CNodeMapOpMetadata **m_ppBins;
  size_t m_nElements;
  UINT m_nBins;
  float m_fOptimalLoad;
  float m_fLoThreshold;
  float m_fHiThreshold;
  size_t m_nHiRehashThreshold;
  size_t m_nLoRehashThreshold;
  ULONG m_nLockCount;
  UINT m_nBlockSize;
  CAtlPlex *m_pBlocks;
  CNodeMapOpMetadata *m_pFree;
};

/* 499 */
struct CAtlPlex
{
  CAtlPlex *pNext;
  DWORD dwReserved[1];
};

/* 501 */
struct CSimpleStringT
{
  LPWSTR m_pszData;
};

/* 503 */
struct HiveValues
{
  __int64 HKeyValue;
  wchar_t *NameOfHive;
};

/* 502 */
struct RegSystemHive
{
  __int64 typeSystemHive;
  wchar_t *nameHive;
  HiveValues valuesForHive;
  wchar_t *PathToHive;
};

/* 505 */
struct CleanUpBaseObject
{
  void *GetObjectReference;
  void *GetObjectPtr1;
  void *GetObjectPtr2;
  void *GetObjectPtr3;
  void *GetObjectPtr4;
  void *DestructObject;
  void *CheckPointerEqual;
  void *CheckPointerNotEqual;
  void *CheckPointerIsNull;
  void *GetAndDestroyPtr;
  void *DestroyPtr;
  void *FreeBufferPointer;
};

/* 509 */
struct CAutoPbrDelete
{
  RaiiAutoPbrDelete *InterfaceObject;
  void **ObjectPtr;
};

/* 510 */
struct ResetOpt
{
  DWORD scenarioType;
  BYTE m_WipeDataCheck;
  BYTE m_OverWriteSpace;
  BYTE m_PreserveWorkplaceCheck;
  BYTE m_UsePayloadCheck;
  __int64 m_member5;
};

/* 514 */
union __declspec(align(8)) HandlerOp
{
  CAutoPbrDelete RaiiHandlerObj;
  DWORD HandlerMetadataVal;
};

/* 516 */
struct Args
{
  DWORD nHash;
  DWORD iBin;
};

/* 515 */
union cleanup2
{
  CString *IdType;
  Args args;
};

/* 517 */
struct __cppobj OpRunDeleteUserData : BaseOperation
{
  PathProperty m_TargetPath;
  StringListProperty m_Exceptions;
};

/* 523 */
struct __cppobj Int64Property : Property
{
  __int64 m_int64_member;
};

/* 522 */
struct __cppobj OpDeleteOldOs : BaseOperation
{
  Int64Property m_TotalBytesToDelete;
};

/* 524 */
struct __cppobj OpArchiveUserData : BaseOperation
{
  StringListProperty m_Exceptions;
};

/* 525 */
struct __cppobj ResetScenario : DerivedScenarioType1
{
};

/* 532 */
struct __cppobj OpMigrateOEMExtensions : BaseOperation
{
};

/* 533 */
struct RunCommand
{
  CString pFolderOrigin;
  CString m_PathScriptPayload;
  CString m_Parameter;
  DWORD m_DurationPayload;
};

/* 534 */
struct CAtlMapRunCommand
{
  CNodeRunCommand **m_ppBins;
  size_t m_nElements;
  UINT m_nBins;
  float m_fOptimalLoad;
  float m_fLoThreshold;
  float m_fHiThreshold;
  size_t m_nHiRehashThreshold;
  size_t m_nLoRehashThreshold;
  ULONG m_nLockCount;
  UINT m_nBlockSize;
  CAtlPlex *m_pBlocks;
  CNodeRunCommand *m_pFree;
};

/* 536 */
struct CPairMapRunCommand
{
  UINT m_key;
  RunCommand m_value;
};

/* 535 */
#pragma pack(push, 8)
struct __cppobj CNodeRunCommand : CPairMapRunCommand
{
  CNodeRunCommand *m_pNext;
  UINT m_nHash;
};
#pragma pack(pop)

/* 538 */
struct BareMetalConfig
{
  CString m_DiskPartScriptPath;
  __int64 m_MinSize;
  DWORD m_OsPartition;
  DWORD m_WinRePartition;
  DWORD m_EntryWinRePath;
  DWORD padding1;
  DWORD m_RecoveryImagePartition;
  DWORD padding2;
  DWORD m_RecoveryImagePath;
  DWORD padding3;
  DWORD m_RecImageIndex;
  DWORD m_RestoreFromIndex;
  DWORD m_CheckSystemDisk;
};

/* 537 */
struct Extensibility
{
  CAtlMapRunCommand m_Command;
  bool m_check;
  BareMetalConfig m_BareConfig;
};

/* 540 */
union CounterMember
{
  DWORD dwNumberValue;
  CString *m_CStr;
};

/* 539 */
struct Entry
{
  CString m_StringNode;
  DWORD dwPropertyType;
  bool bCheckSet;
  CounterMember m_UnionEntry;
};

/* 541 */
struct ComExec
{
  CString *CommandLine;
  RaiiAutoPbrDelete *m_autodel;
  __int64 m_member3;
  __int64 m_member4;
};

/* 542 */
struct __cppobj OpExecSetup : BaseOperation
{
  __int64 m0;
  __int64 m1;
  __int64 m2;
  CString m4;
  BoolProperty m_CompletedDiskEstimate;
  BoolProperty m_Committed;
  UInt64Property m_DiskEstimate;
  StringProperty m_TargetVolume;
  BoolProperty m_ApplyImage;
  PathProperty m_ImagePath;
  IntProperty m_ImageIndex;
  PathListProperty m_ImageRefs;
  BoolProperty m_CompactApply;
  BoolProperty m_ReconstructOs;
  DWORD m5;
  DWORD padding1;
  BoolProperty m_EnableRollBack;
  GuidProperty m_RollbackOs;
  __int64 m17;
  __int64 m18;
  __int64 m19;
  DWORD m20;
  __int64 m21;
  __int64 m22;
  __int64 m23;
  DWORD m24;
  DWORD m25;
  BoolProperty m_MigrateDrivers;
  BoolProperty m_MigrateData;
  BoolProperty m_SkipMachineOOBE;
  BoolProperty m_MigrateProfiles;
  PathProperty m_MigrationXml;
  BoolProperty m_ResetOnline;
  BoolProperty m_NarratorProgressOnline;
  BoolProperty m_RollbackTest;
  StringProperty m_SetupSources;
  GuidProperty m_NewOsBootEntry;
};

/* 546 */
struct BuiltInOperationsEntry
{
  CString OpName;
  void *MethodFunction;
};

