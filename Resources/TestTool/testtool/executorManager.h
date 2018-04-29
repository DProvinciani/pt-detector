#ifndef _REMEDIATOR_MANAGER_H_
#define _REMEDIATOR_MANAGER_H_

#include "helpers.h"
#include "executor.h"

class ExecutorManager
{
public:
	template <typename T>
	void AddExecutor(std::shared_ptr<T>& executor)
	{
		m_executors.push_back(executor);
	}

	bool RunExecutor(const TestCommon::ExecutorsMode mode,
					 TestCommon::TestData &data);

	ExecutorManager::ExecutorManager() {}

private:
	std::vector<std::shared_ptr<Executor>> m_executors;
};

#endif