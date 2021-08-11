/**
 * @file utils.cpp
 *
 * @copyright 2021 extratype
 */

#include "utils.hpp"

namespace chunkdisk
{

DWORD ConvertUTF8(const u8* text, int size, std::wstring& result)
{
    try
    {
        auto wchar_size = MultiByteToWideChar(
            CP_UTF8, 0,
            recast<LPCCH>(text), size, nullptr, 0);
        if (!wchar_size) return GetLastError();

        auto wbuf = std::unique_ptr<WCHAR[]>(new WCHAR[wchar_size + 1]());
        wchar_size = MultiByteToWideChar(
            CP_UTF8, 0,
            recast<LPCCH>(text), size, wbuf.get(), wchar_size + 1);
        if (!wchar_size) return GetLastError();

        if (wbuf[wchar_size - 1] == '\0') wchar_size -= 1;
        result.append(wbuf.get(), wchar_size);
        return ERROR_SUCCESS;
    }
    catch (const std::bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
}

DWORD GetThreadCount(PDWORD ThreadCount)
{
    DWORD Result;
    DWORD_PTR ProcessMask, SystemMask;

    if (!GetProcessAffinityMask(GetCurrentProcess(), &ProcessMask, &SystemMask)) return GetLastError();
    for (Result = 0; 0 != ProcessMask; ProcessMask >>= 1) Result += ProcessMask & 1;
    *ThreadCount = Result;
    return ERROR_SUCCESS;
}


void SetScsiStatus(SPD_IOCTL_STORAGE_UNIT_STATUS* status, u8 sense_key, u8 asc)
{
    status->ScsiStatus = SCSISTAT_CHECK_CONDITION;
    status->SenseKey = sense_key;
    status->ASC = asc;
}

void SetScsiStatus(SPD_IOCTL_STORAGE_UNIT_STATUS* status, u8 sense_key, u8 asc, u64 info)
{
    SetScsiStatus(status, sense_key, asc);
    status->Information = info;
    status->InformationValid = 1;
}

}
