/**
 * @file main.cpp
 *
 * @copyright 2021 extratype
 */

#include "utils.hpp"
#include "params.hpp"
#include "service.hpp"
#include "worker.hpp"
#include <memory>
#include <numeric>
#include <filesystem>

using std::bad_alloc;
using std::unique_ptr;
using std::wstring;
using std::vector;

namespace fs = std::filesystem;

namespace chunkdisk
{

// sector size, 512 or 4096
static constexpr auto BLOCK_SIZE = u32(512);

// align with the underlying hardware, 4096 will work
static constexpr auto PAGE_SIZE = u32(4096);

// must be a multiple of PAGE_SIZE, typically 64K
static constexpr auto MAX_TRANSFER_LENGTH = u32(64 * 1024);

// maximum number of cached pages (write through)
static constexpr auto MAX_PAGES = u32(1024);

// maximum operating bytes expected per worker
static constexpr auto WORKER_CAPACITY = u32(1024 * 1024);

static constexpr auto MAX_WORKERS = u32(MAXIMUM_WAIT_OBJECTS);

struct ChunkDisk
{
    ChunkDiskService service;
    vector<unique_ptr<ChunkDiskWorker>> workers;

    explicit ChunkDisk(ChunkDiskParams params, SPD_STORAGE_UNIT* storage_unit)
        : service(std::move(params), storage_unit, MAX_PAGES) {}

    ~ChunkDisk() { SpdStorageUnitDelete(service.storage_unit); }
};

/*
 * read .chunkdisk file
 *
 * disk size in bytes: must be a multiple of PAGE_SIZE
 * chunk size in bytes: must be a multiple of PAGE_SIZE
 * number path/to/dir...: max. # of chunks in part directory
 */
DWORD ReadChunkDiskParams(PCWSTR chunkdisk_file, ChunkDiskParams& params)
{
    try
    {
        // read .chunkdisk and convert to wstr
        auto h = FileHandle(CreateFileW(
            chunkdisk_file, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!h) return GetLastError();

        auto size = LARGE_INTEGER();
        if (!GetFileSizeEx(h.get(), &size)) return GetLastError();
        if (size.HighPart != 0) return ERROR_ARITHMETIC_OVERFLOW;
        if (size.LowPart == 0) return ERROR_INVALID_PARAMETER;

        auto buf = unique_ptr<u8[]>(new u8[size_t(size.LowPart)]);
        auto bytes_read = DWORD();
        if (!ReadFile(h.get(), buf.get(), size.LowPart, &bytes_read, nullptr)) return GetLastError();

        auto wbuf = wstring();
        auto err = ConvertUTF8(buf.get(), bytes_read, wbuf);
        if (err != ERROR_SUCCESS) return err;

        // parse .chunkdisk
        buf.reset();

        // disk size
        auto* state = PWSTR();
        auto* token = wcstok_s(wbuf.data(), L"\n", &state);
        auto* endp = PWSTR();
        if (!token) return ERROR_INVALID_PARAMETER;
        auto disk_size = wcstoull(token, &endp, 10);
        if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE) return ERROR_INVALID_PARAMETER;

        // chunk size
        token = wcstok_s(nullptr, L"\n", &state);
        if (!token) return ERROR_INVALID_PARAMETER;
        auto chunk_size = wcstoull(token, &endp, 10);
        if (token == endp || (*endp != L'\r' && *endp != L'\0') || errno == ERANGE) return ERROR_INVALID_PARAMETER;

        // parts
        auto part_max = vector<u64>();
        auto part_dirname = vector<wstring>();

        token = wcstok_s(nullptr, L"\n", &state);
        for (; token; token = wcstok_s(nullptr, L"\n", &state))
        {
            auto pmax = wcstoull(token, &endp, 10);
            if (token == endp || *endp != L' ' || errno == ERANGE) return ERROR_INVALID_PARAMETER;

            auto dirname = wstring(endp + 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'\r') dirname.erase(dirname.size() - 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'\\') dirname.erase(dirname.size() - 1);
            if (!dirname.empty() && dirname[dirname.size() - 1] == L'/')  dirname.erase(dirname.size() - 1);
            auto dirpath = fs::path(std::move(dirname));
            if (!dirpath.is_absolute()) return ERROR_INVALID_PARAMETER;

            part_max.push_back(pmax);
            part_dirname.emplace_back(dirpath.wstring());
        }

        // check parameters
        if (disk_size == 0 || chunk_size == 0) return ERROR_INVALID_PARAMETER;
        if (disk_size % BLOCK_SIZE || chunk_size > disk_size) return ERROR_INVALID_PARAMETER;
        if (chunk_size % BLOCK_SIZE) return ERROR_INVALID_PARAMETER;

        auto chunk_count = (disk_size + (chunk_size - 1)) / chunk_size;
        if (chunk_count == 0) return ERROR_INVALID_PARAMETER;
        if (chunk_count > std::accumulate(part_max.begin(), part_max.end(), 0ull)) return ERROR_INVALID_PARAMETER;
        auto chunk_length = chunk_size / BLOCK_SIZE;

        if (disk_size % PAGE_SIZE) return ERROR_INVALID_PARAMETER;
        if (chunk_size % PAGE_SIZE) return ERROR_INVALID_PARAMETER;
        // if (PAGE_SIZE % BLOCK_SIZE) return ERROR_INVALID_PARAMETER;

        params.block_size = BLOCK_SIZE;
        params.page_length = PAGE_SIZE / BLOCK_SIZE;
        params.block_count = disk_size / BLOCK_SIZE;
        params.chunk_length = chunk_length;
        params.chunk_count = chunk_count;
        params.part_max = std::move(part_max);
        params.part_dirname = std::move(part_dirname);
    }
    catch (const bad_alloc&)
    {
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    return ERROR_SUCCESS;
}

ChunkDisk* StorageUnitChunkDisk(SPD_STORAGE_UNIT* StorageUnit)
{
    return recast<ChunkDisk*>(StorageUnit->UserContext);
}

// SPD_STORAGE_UNIT_INTERFACE operations
// op_kind: one of READ_CHUNK, WRITE_CHUNK, UNMAP_CHUNK
BOOLEAN PostWork(SPD_STORAGE_UNIT* StorageUnit, ChunkOpKind op_kind, u64 block_addr, u32 count)
{
    auto context = SpdStorageUnitGetOperationContext();

    if (op_kind == UNMAP_CHUNK)
    {
        // for UNMAP_CHUNK use the first address to choose a worker
        // ChunkDiskWorker::PostWork() ignores block_addr
        auto* descs = recast<SPD_UNMAP_DESCRIPTOR*>(context->DataBuffer);
        if (count) block_addr = descs[0].BlockAddress;
    }

    // schedule requests, see docs/asyncio.txt
    auto* cdisk = StorageUnitChunkDisk(StorageUnit);
    auto post_ft = GetSystemFileTime();

    auto err = [cdisk, op_kind, block_addr, count, context]() -> DWORD
    {
        auto& workers = cdisk->workers;
        // choose worker based on address
        auto start = (block_addr / cdisk->service.params.ByteBlock(WORKER_CAPACITY).first) % (workers.size());

        for (auto i = start; i < workers.size(); ++i)
        {
            auto err = workers[i]->PostWork(context, op_kind, block_addr, count);
            if (err != ERROR_BUSY) return err;
        }
        for (auto i = 0; i < start; ++i)
        {
            auto err = workers[i]->PostWork(context, op_kind, block_addr, count);
            if (err != ERROR_BUSY) return err;
        }

        // all busy, wait for start
        workers[start]->Wait();
        return workers[start]->PostWork(context, op_kind, block_addr, count);
    }();
    if (err == ERROR_IO_PENDING) cdisk->service.SetPostFileTime(post_ft);

    if (err != ERROR_IO_PENDING && err != ERROR_SUCCESS)
    {
        auto& status = context->Response->Status;
        if (status.ScsiStatus == SCSISTAT_GOOD)
        {
            SetScsiError(&status, SCSI_SENSE_HARDWARE_ERROR, SCSI_ADSENSE_NO_SENSE);
        }
    }
    return (err == ERROR_IO_PENDING) ? FALSE : TRUE;
}

BOOLEAN Read(SPD_STORAGE_UNIT* StorageUnit,
                    PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
                    SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    return PostWork(StorageUnit, READ_CHUNK, BlockAddress, BlockCount);
}

BOOLEAN Write(SPD_STORAGE_UNIT* StorageUnit,
                     PVOID Buffer, UINT64 BlockAddress, UINT32 BlockCount, BOOLEAN FlushFlag,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported || FlushFlag);

    return PostWork(StorageUnit, WRITE_CHUNK, BlockAddress, BlockCount);
}

// Flush(0, 0) requested at exit
BOOLEAN Flush(SPD_STORAGE_UNIT* StorageUnit,
                     UINT64 BlockAddress, UINT32 BlockCount,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.CacheSupported);

    // unbuffered, pages write through, nothing to flush
    // metadata flushed when handles are closed in ChunkDiskWorker::IdleWork()
    return TRUE;
}

BOOLEAN Unmap(SPD_STORAGE_UNIT* StorageUnit,
                     SPD_UNMAP_DESCRIPTOR Descriptors[], UINT32 Count,
                     SPD_STORAGE_UNIT_STATUS* Status)
{
    SpdWarnOnce(!StorageUnit->StorageUnitParams.WriteProtected);
    SpdWarnOnce(StorageUnit->StorageUnitParams.UnmapSupported);

    // Descriptors is just Buffer, writable
    // merge ranges
    if (Count == 0) return TRUE;

    std::sort(Descriptors, Descriptors + Count,
              [](const auto& a, const auto& b)
              {
                  return (a.BlockAddress < b.BlockAddress) ||
                         (a.BlockAddress == b.BlockAddress) && (a.BlockCount < b.BlockCount);
              });

    auto new_count = UINT32();
    auto prev_addr = Descriptors[0].BlockAddress;
    auto prev_count = Descriptors[0].BlockCount;

    for (UINT32 I = 0; I < Count; ++I)
    {
        auto addr = Descriptors[I].BlockAddress;
        auto count = Descriptors[I].BlockCount;

        if (count == 0) continue;

        if (addr <= prev_addr + prev_count)
        {
            auto count_ext = max(addr + count, prev_addr + prev_count) - prev_addr;
            if (count_ext <= UINT32(-1))
            {
                // no overflow
                prev_count = UINT32(count_ext);
                continue;
            }
        }

        Descriptors[new_count] = {prev_addr, prev_count, 0};
        ++new_count;
        prev_addr = addr;
        prev_count = count;
    }

    Descriptors[new_count] = {prev_addr, prev_count, 0};
    ++new_count;

    return PostWork(StorageUnit, UNMAP_CHUNK, 0, new_count);
}

static SPD_STORAGE_UNIT_INTERFACE CHUNK_DISK_INTERFACE =
{
    Read,
    Write,
    Flush,
    Unmap,
};

DWORD CreateStorageUnit(PWSTR chunkdisk_file, BOOLEAN write_protected, PWSTR pipe_name, unique_ptr<ChunkDisk>& cdisk_out)
{
    // read chunkdisk file
    auto params = ChunkDiskParams();
    auto err = ReadChunkDiskParams(chunkdisk_file, params);
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: parsing failed with error %lu", err);
        return err;
    }

    // create WinSpd unit
    SPD_STORAGE_UNIT* unit = nullptr;
    err = [&params, write_protected, pipe_name, &unit]() -> DWORD
    {
        constexpr wchar_t ProductId[] = L"ChunkDisk";
        constexpr wchar_t ProductRevision[] = L"0.6";   // FIXME bump
        auto unit_params = SPD_STORAGE_UNIT_PARAMS();

        UuidCreate(&unit_params.Guid);
        unit_params.BlockCount = params.block_count;
        unit_params.BlockLength = params.block_size;
        unit_params.MaxTransferLength = MAX_TRANSFER_LENGTH;
        if (WideCharToMultiByte(
                CP_UTF8, 0,
                ProductId, lstrlenW(ProductId),
                LPSTR(unit_params.ProductId), sizeof(unit_params.ProductId),
                nullptr, nullptr) == 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        if (WideCharToMultiByte(
                CP_UTF8, 0,
                ProductRevision, lstrlenW(ProductRevision),
                LPSTR(unit_params.ProductRevisionLevel), sizeof(unit_params.ProductRevisionLevel),
                nullptr, nullptr) == 0)
        {
            return ERROR_INVALID_PARAMETER;
        }
        unit_params.WriteProtected = write_protected;
        unit_params.CacheSupported = TRUE;
        unit_params.UnmapSupported = TRUE;

        auto err = SpdStorageUnitCreate(pipe_name, &unit_params, &CHUNK_DISK_INTERFACE, &unit);
        if (err != ERROR_SUCCESS) return err;
        return ERROR_SUCCESS;
    }();
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: cannot create ChunkDisk: error %lu", err);
        return err;
    }

    // create ChunkDisk
    auto cdisk = unique_ptr<ChunkDisk>();
    try
    {
        // unit will be deleted when cdisk is deleted
        cdisk = std::make_unique<ChunkDisk>(std::move(params), unit);
        unit->UserContext = cdisk.get();
    }
    catch (const bad_alloc&)
    {
        SpdStorageUnitDelete(unit);
        SpdLogErr(L"error: not enough memory to start");
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    err = cdisk->service.Start();
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: cannot initialize ChunkDisk: error %lu", err);
        return err;
    }

    cdisk_out = std::move(cdisk);
    return ERROR_SUCCESS;
}

DWORD StopWorkers(ChunkDisk& cdisk, DWORD timeout_ms = INFINITE)
{
    vector<HANDLE> handles;
    auto err = [&cdisk, timeout_ms, &handles]() -> DWORD
    {
        try
        {
            handles.reserve(cdisk.workers.size());
            for (auto& worker : cdisk.workers)
            {
                HANDLE h;
                auto err = worker->StopAsync(h);
                if (err != ERROR_SUCCESS) return err;
                handles.push_back(h);
            }

            if (handles.empty()) return ERROR_SUCCESS;
            return WaitForMultipleObjects(handles.size(), &handles.front(), TRUE, timeout_ms);
        }
        catch (const bad_alloc&)
        {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
    }();

    for (auto h : handles) CloseHandle(h);
    return err;
}

// num_workers: should be positive
DWORD StartWorkers(ChunkDisk& cdisk, u32 num_workers)
{
    auto& workers = cdisk.workers;
    auto err = DWORD(ERROR_SUCCESS);

    try
    {
        workers.reserve(num_workers);
        for (u32 i = 0; i < num_workers; ++i)
        {
            auto it = workers.emplace(workers.end(), new ChunkDiskWorker(cdisk.service));
            err = (*it)->Start();
            if (err != ERROR_SUCCESS) break;
        }
    }
    catch (const bad_alloc&)
    {
        err = ERROR_NOT_ENOUGH_MEMORY;
    }

    if (err != ERROR_SUCCESS) StopWorkers(cdisk);
    return err;
}

vector<unique_ptr<ChunkDiskWorker>>& GetWorkers(SPD_STORAGE_UNIT* StorageUnit)
{
    return StorageUnitChunkDisk(StorageUnit)->workers;
}

}   // namespace chunkdisk

namespace
{

constexpr PCWSTR PROGNAME = L"chunkdisk";

[[noreturn]] void usage()
{
    static WCHAR usage[] = L""
        "usage: %s OPTIONS\n"
        "\n"
        "options:\n"
        "    -f ChunkDiskFile                    Chunkdisk metadata file (name.chunkdisk)\n"
        "    -W 0|1                              Disable/enable writes (deflt: enable)\n"
        "    -t Number                           Number of threads (deflt: automatic)\n"
        "    -d -1                               Debug flags\n"
        "    -D DebugLogFile                     Debug log file; - for stderr\n"
        "    -p \\\\.\\pipe\\PipeName                Listen on pipe; omit to use driver\n"
        "";

    SpdLogErr(usage, PROGNAME);
    ExitProcess(ERROR_INVALID_PARAMETER);
}

ULONG argtol(wchar_t** argp, ULONG deflt)
{
    if (argp[0] == nullptr)
        usage();

    PWSTR endp;
    ULONG ul = wcstol(argp[0], &endp, 10);
    return (argp[0][0] != L'\0' && *endp == L'\0') ? ul : deflt;
}

PWSTR argtos(wchar_t** argp)
{
    if (argp[0] == nullptr)
        usage();

    return argp[0];
}

SPD_GUARD ConsoleCtrlGuard = SPD_GUARD_INIT;

BOOL WINAPI ConsoleCtrlHandler(DWORD CtrlType)
{
    SpdGuardExecute(&ConsoleCtrlGuard, (void(*)(PVOID))(SpdStorageUnitShutdown));
    return TRUE;
}

}   // namespace

int wmain(int argc, wchar_t** argv)
{
    wchar_t** argp;
    PWSTR ChunkDiskFile = nullptr;
    ULONG WriteAllowed = 1;
    ULONG NumThreads = 0;
    PWSTR DebugLogFile = nullptr;
    PWSTR PipeName = nullptr;
    ULONG DebugFlags = 0;

    for (argp = argv + 1; argp[0] != nullptr; argp++)
    {
        if (argp[0][0] != L'-')
            break;
        switch (argp[0][1])
        {
        case L'?':
            usage();
        case L'f':
            ChunkDiskFile = argtos(++argp);
            break;
        case L'W':
            WriteAllowed = argtol(++argp, WriteAllowed);
            break;
        case L't':
            NumThreads = argtol(++argp, NumThreads);
            break;
        case L'd':
            DebugFlags = argtol(++argp, DebugFlags);
            break;
        case L'D':
            DebugLogFile = argtos(++argp);
            break;
        case L'p':
            PipeName = argtos(++argp);
            break;
        default:
            usage();
        }
    }

    if (argp[0] != nullptr || ChunkDiskFile == nullptr)
        usage();

    DWORD err;
    if (NumThreads == 0)
    {
        err = chunkdisk::GetThreadCount(&NumThreads);
        if (err != ERROR_SUCCESS)
        {
            SpdLogErr(L"error: failed to get number of CPU threads with error %lu", err);
            return err;
        }
    }
    if (NumThreads > chunkdisk::MAX_WORKERS)
    {
        SpdLogWarn(L"warning: number of threads capped to %u", chunkdisk::MAX_WORKERS);
        NumThreads = chunkdisk::MAX_WORKERS;
    }

    HANDLE DebugLogHandle;
    if (DebugLogFile != nullptr)
    {
        if (DebugLogFile[0] == L'-' && DebugLogFile[1] == L'\0')
            DebugLogHandle = GetStdHandle(STD_ERROR_HANDLE);
        else
            DebugLogHandle = CreateFileW(
                DebugLogFile,
                FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
        if (INVALID_HANDLE_VALUE == DebugLogHandle) {
            err = GetLastError();
            SpdLogErr(L"error: cannot open debug log file");
            return err;
        }
        SpdDebugLogSetHandle(DebugLogHandle);
    }

    auto cdisk = unique_ptr<chunkdisk::ChunkDisk>();
    err = chunkdisk::CreateStorageUnit(ChunkDiskFile, !WriteAllowed, PipeName, cdisk);
    if (err != ERROR_SUCCESS) return err;
    err = chunkdisk::StartWorkers(*cdisk, NumThreads);
    if (err != ERROR_SUCCESS) return err;

    auto* storage_unit = cdisk->service.storage_unit;
    SpdStorageUnitSetDebugLog(storage_unit, DebugFlags);
    err = SpdStorageUnitStartDispatcher(cdisk->service.storage_unit, 1);
    if (err != ERROR_SUCCESS)
    {
        SpdLogErr(L"error: cannot start ChunkDisk: error %lu", err);
        return err;
    }

    SpdLogInfo(L"%s -f %s -W %u -t %d%s%s",
        PROGNAME,
        ChunkDiskFile,
        !!WriteAllowed,
        NumThreads,
        (nullptr != PipeName) ? L" -p " : L"",
        (nullptr != PipeName) ? PipeName : L"");

    SpdGuardSet(&ConsoleCtrlGuard, storage_unit);
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    SpdStorageUnitWaitDispatcher(storage_unit);
    SpdGuardSet(&ConsoleCtrlGuard, nullptr);

    chunkdisk::StopWorkers(*cdisk);
    cdisk.reset();
    return ERROR_SUCCESS;
}
