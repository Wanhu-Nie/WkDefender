/**************************************************/
/*  WkDefender Agent — FileSystem 子模块内部共享头文件  */
/*                                                  */
/*  2026-09-14 重构: 自 FileSystem/IocDocumentScanner  */
/*  .h 拆出。本头仅存放 FileAnalyzer 内部共享的限制宏, */
/*  仅供 FileSystem 子模块内部 .c 文件使用。          */
/*  CFB/OLE 结构体与内部 static helper 声明在        */
/*  FileAnalyzer.c 内部自包含，不外泄。              */
/**************************************************/

#pragma once

#include <windows.h>
#include "../Include/FileSystem/FileAnalyzer.h"  /* WKD_DOC_* 公共类型 */

/**************************************************/
/*               限制常量                           */
/*  (原 IocDocumentScanner.c 文件内定义, 提升至此共享) */
/**************************************************/

#define WKD_DOC_MAX_FILE_SIZE    (100u * 1024u * 1024u)
#define WKD_DOC_MAX_STRING_EXTRACT (1u * 1024u * 1024u)
#define WKD_DOC_MAX_JAVASCRIPT   (10u * 1024u * 1024u)
#define WKD_DOC_MAX_OLE_OBJECT   (64u * 1024u * 1024u)
#define WKD_DOC_MAX_FAT_STEPS    200000
#define WKD_DOC_MINI_CUTOFF      4096
#define WKD_DOC_MAX_DIR_ENTRIES  10000
#define WKD_DOC_MAX_DIFAT_CHAIN  1000
#define WKD_DOC_MAX_PDF_OBJECTS  5000
#define WKD_DOC_PDF_OBJECT_CAP   (1u * 1024u * 1024u)
#define WKD_DOC_DDE_SCAN_CAP     (16u * 1024u * 1024u)
#define WKD_DOC_VBA_MAX_CODE     100000
#define WKD_DOC_VBA_MAX_MODULES  200
