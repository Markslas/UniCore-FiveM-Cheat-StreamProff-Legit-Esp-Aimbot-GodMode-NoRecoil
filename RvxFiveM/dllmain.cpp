#include <Windows.h>
#include <stdio.h>
#include <cstdint>
#include <functional>
# include "minhook/include/MinHook.h"
#include <iostream>
extern "C" {
#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"
#include "lua/lvm.h"
#include "lua/ldo.h"


}
using namespace std;
__int64 state;


void* placeHook(DWORD address, void* hookadr, bool revert) {
	DWORD oldprot;
	if (!revert) {

		void* oldmem = new void*;
		void* result = new void*;
		memcpy(oldmem, (void*)address, sizeof(void*) * 4);
		VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldprot);
		*(char*)address = 0xE9; *(DWORD*)(address + 1) = (DWORD)hookadr - address - 5;
		memcpy(result, oldmem, sizeof(void*) * 4);
		VirtualProtect((LPVOID)address, 1, oldprot, &oldprot);
		return result;
	}
	else {

		VirtualProtect((LPVOID)address, 1, PAGE_EXECUTE_READWRITE, &oldprot);
		memcpy((void*)address, hookadr, sizeof(void*) * 4);
		VirtualProtect((LPVOID)address, 1, oldprot, &oldprot);

		return NULL;
	}
}
uint64_t csLuaBase;

typedef int(__fastcall* LuaScriptRuntime__RunFileInternalProto)(uint64_t _this, const char* scriptName, std::function<int(const char*)> loadFunction);
const auto LuaScriptRuntime__RunFileInternal = (LuaScriptRuntime__RunFileInternalProto)(csLuaBase + 0x27459);
LuaScriptRuntime__RunFileInternalProto LuaScriptRuntime__RunFileInternalPtr = nullptr;
typedef struct lua_State f_lua_State;
lua_State* fiveM_global_state = nullptr;

int sub_180035CD0(uintptr_t _this, const char* scriptName, std::function<int(const char*)> loadFunction) {
	fiveM_global_state = *(f_lua_State**)(_this + 72);
	return LuaScriptRuntime__RunFileInternal(_this, scriptName, loadFunction);
}

void* initializeHook(bool enabled) {
	csLuaBase = (uint64_t)GetModuleHandleW(L"citizen-scripting-lua.dll");

	void* Old = placeHook(csLuaBase + 0x27459, sub_180035CD0, false);
	while (state == 0) Sleep(100);
	placeHook(csLuaBase + 0x27459, Old, true);
	MessageBoxA(NULL, "HOOK END", NULL, NULL);
	return 0;

	//rlua_settop(luaState, 0);
}

lua_State* m_state;
using InvokeNative_t = int(__fastcall*)(lua_State* L);



static int Lua_Print(lua_State* L)
{
	int n = lua_gettop(L); /* number of arguments */
	int i;
	lua_getglobal(L, "tostring");
	for (i = 1; i <= n; i++)
	{
		const char* s;
		size_t l;
		lua_pushvalue(L, -1); /* function to be called */
		lua_pushvalue(L, i); /* value to print */
		lua_call(L, 1, 1);
		s = lua_tolstring(L, -1, &l); /* get result */
		if (s == NULL)
			return luaL_error(L, "'tostring' must return a string to 'print'");
		

		lua_pop(L, 1); /* pop result */
	}
	//	ScriptTrace("\n");
	return 0;
}

enum class LuaMetaFields
{
	PointerValueInt,
	PointerValueFloat,
	PointerValueVector,
	ReturnResultAnyway,
	ResultAsInteger,
	ResultAsLong,
	ResultAsFloat,
	ResultAsString,
	ResultAsVector,
	ResultAsObject,
	Max
};

static uint8_t g_metaFields[(int)LuaMetaFields::Max];


template<LuaMetaFields metaField>
int Lua_GetMetaField(lua_State* L)
{
	lua_pushlightuserdata(L, &g_metaFields[(int)metaField]);

	return 1;
}

struct PointerFieldEntry
{
	bool empty;
	uintptr_t value;

	PointerFieldEntry()
	{
		empty = true;
	}
};

struct PointerField
{
	PointerFieldEntry data[64];
};

PointerField m_pointerFields[3];

template<LuaMetaFields MetaField>
int Lua_GetPointerField(lua_State* L)
{
	auto pointerFields = m_pointerFields;
	auto pointerFieldStart = &pointerFields[(int)MetaField];

	static uintptr_t dummyOut;
	PointerFieldEntry* pointerField = nullptr;

	for (int i = 0; i < _countof(pointerFieldStart->data); i++)
	{
		if (pointerFieldStart->data[i].empty)
		{
			pointerField = &pointerFieldStart->data[i];
			pointerField->empty = false;

			// to prevent accidental passing of arguments like _r, we check if this is a userdata
			if (lua_isnil(L, 1) || lua_islightuserdata(L, 1) || lua_isuserdata(L, 1))
			{
				pointerField->value = 0;
			}
			else if (MetaField == LuaMetaFields::PointerValueFloat)
			{
				float value = static_cast<float>(luaL_checknumber(L, 1));

				pointerField->value = *reinterpret_cast<uint32_t*>(&value);
			}
			else if (MetaField == LuaMetaFields::PointerValueInt)
			{
				intptr_t value = luaL_checkinteger(L, 1);

				pointerField->value = value;
			}

			break;
		}
	}

	lua_pushlightuserdata(L, (pointerField) ? static_cast<void*>(pointerField) : &dummyOut);
	return 1;
}
#include <winternl.h>

int Lua_LoadNative(lua_State* L)
{
	return ((InvokeNative_t)(GetModuleHandleW(L"citizen-scripting-lua.dll") + 0x25580))(L);
}

int Lua_InvokeNative(lua_State* L)
{
	return ((InvokeNative_t)(GetModuleHandleW(L"citizen-scripting-lua.dll") + 0x29100))(L);
}
HMODULE modules = GetModuleHandle("ntdll.dll");

typedef NTSTATUS(WINAPI* NTQUERYINFOMATIONTHREAD)(HANDLE, LONG, PVOID, ULONG, PULONG);
NTQUERYINFOMATIONTHREAD test_nt_thread = (NTQUERYINFOMATIONTHREAD)GetProcAddress(modules, "NtQueryInformationThread");

struct THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} tbi{ NULL };

struct _TEB_FIVEM
{
	NT_TIB Tib;
	PVOID EnvironmentPointer;
	CLIENT_ID Cid;
	PVOID ActiveRpcInfo;
	PVOID ThreadLocalStoragePointer;
};
unsigned int tlsIdx = *(unsigned int*)((uint64_t)GetModuleHandle("adhesive.dll") + 0x1F5BC00);


int testmain() {
	//initializeHook(true);
	AllocConsole();
	SetConsoleTitleA("TEST CONSOLE");
	AttachConsole(GetCurrentProcessId());
	freopen_s((FILE**)stdin, "conin$", "r", stdin);
	freopen_s((FILE**)stdout, "conout$", "w", stdout);



	auto val = *(uint64_t*)(*((uint64_t*)((_TEB_FIVEM*)(tbi.TebBaseAddress))->ThreadLocalStoragePointer + (unsigned int)tlsIdx) + 0x52C0);

	if (val != 0xAFE287220C8335AEui64)
	{

		auto y = val ^ 0xB8663FD607720057ui64;
		int maybe_g = 0;
		_TEB* v141 = NtCurrentTeb();
		uint64_t 	v142 = (32769 * y ^ val) ^ ((32769
			* (y ^ val)) >> 31);
		uint64_t	v143 = _byteswap_uint64(v142 ^ (v142 >> 19));
		uint64_t v144 = (16 * (v143 & 0xF0F0F0F0F0F0F0Fi64)) | ((v143 & 0xF0F0F0F0F0F0F0F0ui64) >> 4);
		uint64_t v145 = (((((v144 & 0xCCCCCCCCCCCCCCCCui64) >> 2) + 4 * (v144 & 0x3333333333333333i64)) & 0xAAAAAAAAAAAAAAAAui64) >> 1)
			+ 2 * ((((v144 & 0xCCCCCCCCCCCCCCCCui64) >> 2) + 4 * (v144 & 0x3333333333333333i64)) & 0x5555555555555555i64);
		uint64_t v146 = ~(maybe_g ^ (0x37BF5BFFA7715B1Di64
			* (_rotl8(v145, 55) ^ _rotl8(v145, 2) ^ _rotl8(v145, 60))));
		uint64_t v147 = (8388609 * ((v146 >> 7) ^ v146 ^ 0x7FFE0330) + 0x4883C522E50BFC60i64);


		std::cout << v147 << std::endl;

		//return v147; /* script run shit */
	}

	return 0;
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:

		DisableThreadLibraryCalls(hMod);
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)testmain, hMod, 0, nullptr);
	
			break;
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}