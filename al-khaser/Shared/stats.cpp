#include "pch.h"
#include "Common.h"

const char* category_names[CAT_COUNT] = { // New categories to be added here. Order must be same as Category enum
	"TLS Callbacks",
	"Debugger Detection",
	"DLL Injection Detection",
	"Generic Sandbox/VM Detection",
	"VirtualBox Detection",
	"VMWare Detection",
	"Virtual PC Detection",
	"QEMU Detection",
	"KVM Detection",
	"Xen Detection",
	"Wine Detection",
	"Parallels Detection",
	"Hyper-V Detection",
	"Timitng Attacks",
	"Analysis Tools",
	//"CODE_INJECTIONS",
	//"ANTI_DISASSM",
	//"DUMPING_CHECK"
};

const wchar_t* w_category_names[CAT_COUNT] = { // New categories to be added here. Order must be same as Category enum
	L"TLS Callbacks",
	L"Debugger Detection",
	L"DLL Injection Detection",
	L"Generic Sandbox/VM Detection",
	L"VirtualBox Detection",
	L"VMWare Detection",
	L"Virtual PC Detection",
	L"QEMU Detection",
	L"KVM Detection",
	L"Xen Detection",
	L"Wine Detection",
	L"Parallels Detection",
	L"Hyper-V Detection",
	L"Timitng Attacks",
	L"Analysis Tools",
	//"CODE_INJECTIONS",
	//"ANTI_DISASSM",
	//"DUMPING_CHECK"
};


static CategoryStat category_stats[CAT_COUNT];
static int total_passed = 0, total_failed = 0;

void stats_init(void) {
	memset(category_stats, 0, sizeof(category_stats));
	total_passed = 0;
	total_failed = 0;
}

void stats_record(Category cat, int result) {
	if (cat < 0 || cat >= CAT_COUNT)
		return;
	if (result == TRUE) {
		category_stats[cat].failed++;
		total_failed++;
	} else {
		category_stats[cat].passed++;
		total_passed++;
	}
}

void stats_print(void) {
	printf("\n==== Per-Category Statistics ====\n");
	LOG_PRINT(_T("==== Per-Category Statistics ===="));

	/* log to file*/
	TCHAR buffer[256] = _T("");
	
	for (int i = 0; i < CAT_COUNT; ++i) {
		printf("%-40s: Passed %3d | Failed %3d\n",
			category_names[i], category_stats[i].passed, category_stats[i].failed);
		_stprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("%-40s: Passed %3d | Failed %3d"), w_category_names[i], category_stats[i].passed, category_stats[i].failed);
		LOG_PRINT(buffer);
	}
	printf("\n==== Overall Statistics ====\n");
	LOG_PRINT(_T("==== Overall Statistics ===="));
	printf("Total checks passed: %d\n", total_passed);
	_stprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("Total checks passed: %d"), total_passed);
	LOG_PRINT(buffer);
	printf("Total checks failed: %d\n", total_failed);
	_stprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("Total checks failed: %d"), total_failed);
	LOG_PRINT(buffer);
}