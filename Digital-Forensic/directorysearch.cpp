/* BOB5_YK_B1_name */

#include <stdio.h>
#include <tchar.h>
#include <locale.h>
#include <Windows.h>

void filelist(TCHAR *path, int depth) {
	HANDLE hfind;
	WIN32_FIND_DATA wfd;
	TCHAR dir[MAX_PATH];
	TCHAR subdir[MAX_PATH];
	int i;

	wcscpy_s(dir, path);
	wcscat_s(dir, L"*");	// 디렉토리의 모든 파일 탐색을 위함
	
	hfind = FindFirstFile(dir, &wfd);	// 처음 파일에 대한 정보를 가져온다. 
	if (hfind == INVALID_HANDLE_VALUE) {	// 경로가 존재하지 않는 등 오류가 발생하여 핸들을 얻을 수 없는 경우
		printf("FindFirstFile error! (%d)\n", GetLastError());
	}
	do {
		if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {	// 디렉토리인 경우
			if (wcscmp(wfd.cFileName, L".") && wcscmp(wfd.cFileName, L"..")) {	// 디렉토리가 . 이나 .. 이 아닌경우 
				if (depth > 0) {
					i = depth;
					while (i--) 
						_tprintf(_T("----"));
				}
				_tprintf(_T("----%s <DIR>\n"), wfd.cFileName);			// 디렉토리 출력
				swprintf_s(subdir, L"%s%s\\", path, wfd.cFileName);		// 하위 디렉토리 경로 설정
				filelist(subdir, depth + 1);					// 재귀하여 하위 디렉토리 탐색
			}
		}
		else {	// 일반파일인 경우 
			if (depth > 0) {
				i = depth+1;
				while(i--) 
					_tprintf(_T("    "));

				_tprintf(_T("%s\n"), wfd.cFileName);				// 하위 디렉토리 내 파일 출력
				continue;
			}
			_tprintf(_T("    %s\n"), wfd.cFileName);				// 일반 파일 출력
		}
	} while (FindNextFile(hfind, &wfd));							// 다음 파일에 대한 정보를 가져온다. 
	FindClose(hfind);
}

int _tmain(int argc, TCHAR* argv[])
{
	setlocale(LC_ALL, "Korean");	// 한글 처리
	_tprintf(_T("%s\n"), argv[1]);	// 사용자가 입력한 경로 출력
	filelist(argv[1], 0);
	return 0;
}
