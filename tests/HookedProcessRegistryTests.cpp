#include "HookedProcessRegistry.h"
#include <iostream>
#include <thread>

int HookedProcessRegistryTestsMain()
{
	CHookedProcessRegistry registry;
	registry.Record(41, 100, ERROR_ACCESS_DENIED);
	registry.Record(0, 100, 0);
	registry.Record(41, 0, 0);
	if (!registry.Snapshot().empty()) return 1;
	// Pipe callbacks from different injected processes can arrive concurrently.
	std::thread first([&]() {
		for (int i = 0; i < 1000; ++i) registry.Record(41, 100, 0);
	});
	std::thread second([&]() {
		for (int i = 0; i < 1000; ++i) registry.Record(42, 200, 0);
	});
	first.join();
	second.join();
	registry.Record(41, 100, ERROR_ACCESS_DENIED); // Failed retry cannot remove a live hook.
	CHookedProcessRegistry::Identities recorded = registry.Snapshot();
	if (recorded.size() != 2 || !recorded.count({42, 200}) ||
		!recorded.count({41, 100}) || recorded.count({41, 101})) return 1;
	// A recycled PID is a separate lifetime; delayed reports preserve both identities.
	registry.Record(41, 300, 0);
	registry.Record(41, 100, 0);
	recorded = registry.Snapshot();
	if (recorded.size() != 3 || !recorded.count({41, 300})) return 1;
	std::cout << "HookedProcessRegistry tests passed" << std::endl;
	return 0;
}
