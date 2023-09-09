#include <iostream>
#include <crow.h>
#include <exception>
#include <psapi.h>
#include <Windows.h>
#include <vector>
#include <boost/json.hpp>   // using boost's json because Crow's doesn't have arrays of jsons afaik

bool hasShutdownPrivilege();  // used to check if the process was launched with privilege to shut down the computer


int main()
{
	crow::SimpleApp app;

	CROW_ROUTE(app, "/")
		([]() {
		// TODO: serve the front-end here
		return "Hello, World!";
			});

	CROW_ROUTE(app, "/processes")
		([]() {
		DWORD processIds[1024];
		DWORD cbNeeded;
		if (!EnumProcesses(processIds, sizeof(processIds), &cbNeeded))
			return crow::response(500, "Failed to retrieve process list");

		DWORD numProcesses = cbNeeded / sizeof(DWORD);

		boost::json::array processArray;

		for (DWORD i = 0; i < numProcesses; i++) {
			DWORD processId = processIds[i];
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
			if (hProcess) {
				CHAR processName[MAX_PATH];
				if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName))) {
					PROCESS_MEMORY_COUNTERS_EX pmc;
					if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
						boost::json::object processObject;
						processObject["pid"] = static_cast<int>(processId);
						processObject["process_name"] = processName;
						processObject["memory_usage"] = static_cast<unsigned long>(pmc.PrivateUsage);

						processArray.push_back(std::move(processObject));
					}
				}
				CloseHandle(hProcess);
			}
		}

		boost::json::object responseObject;
		responseObject["processes"] = std::move(processArray);

		std::string responseJson = boost::json::serialize(responseObject);

		return crow::response(responseJson);
		});

	CROW_ROUTE(app, "/kill/<int>").methods("POST"_method)
		([](DWORD pid) {
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
		if (hProcess == NULL)
		{
			std::cout << "Failed to open process with PID: " << pid << std::endl;
			return crow::response(404, "Process not found");
		}

		if (TerminateProcess(hProcess, 0))
		{
			std::cout << "Process with PID " << pid << " terminated successfully." << std::endl;
			CloseHandle(hProcess);
			return crow::response(200, "Process terminated");
		}
		else
		{
			std::cout << "Failed to terminate process with PID: " << pid << std::endl;
			CloseHandle(hProcess);
			return crow::response(500, "Internal Server Error: Failed to terminate process");
		}
			});

	CROW_ROUTE(app, "/power/<string>").methods("POST"_method)
		([](std::string power_option)
			{
				if (power_option == "shutdown")
				{
					if (!hasShutdownPrivilege())
					{
						return crow::response(500, "Process is not privileged to shut down the machine.");
					}
					TCHAR msg[] = TEXT("Shutdown requested by Remote Task Manager");
					InitiateSystemShutdownEx(NULL, msg, 30, TRUE, FALSE, 0);

					return crow::response(200, "Shutting down");
				}
				else if (power_option == "restart")
				{
					if (!hasShutdownPrivilege())
					{
						return crow::response(500, "Process is not privileged to shut down the machine.");
					}
					TCHAR msg[] = TEXT("Restart requested by Remote Task Manager");
					InitiateSystemShutdownEx(NULL, msg, 30, TRUE, TRUE, 0);
					return crow::response(200, "Restarting");
				}
				else 
				{
					return crow::response(400, "Bad Request");
				}
			});

	try 
	{
		app.port(8081).multithreaded().run();
	}
	catch (std::exception e) 
	{
		std::cout << e.what() << '\n';
	}

	return 0;
}

bool hasShutdownPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES privileges;
	LUID shutdownLuid;

	// Open the access token of the current process
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		std::cerr << "Failed to open process token." << std::endl;
		return false;
	}

	// Retrieve the LUID for the shutdown privilege
	if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &shutdownLuid)) {
		std::cerr << "Failed to lookup shutdown privilege LUID." << std::endl;
		CloseHandle(hToken);
		return false;
	}

	// Set up the privileges structure
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = shutdownLuid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Check if the shutdown privilege is enabled
	if (AdjustTokenPrivileges(hToken, FALSE, &privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			std::cerr << "Failed to enable shutdown privilege." << std::endl;
			CloseHandle(hToken);
			return false;
		}
	}
	else {
		std::cerr << "Failed to adjust token privileges." << std::endl;
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hToken);

	return true; // The shutdown privilege is enabled
}