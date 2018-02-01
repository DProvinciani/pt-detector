#include "executorManager.h"

bool ExecutorManager::RunExecutor(const TestCommon::TestExecutorsMode mode,
								  TestCommon::TestData &data)
{
	bool ret = false;

	for (std::vector<std::shared_ptr<Executor>>::const_iterator executorIt = m_executors.begin();
		executorIt != m_executors.end();
		++executorIt)
	{
		if (*executorIt != nullptr)
		{
			std::shared_ptr<Executor> executor = *executorIt;
			if (executor->GetMode() == mode)
			{
				ret = executor->Execute(data);
				break;
			}
		}
	}

	return ret;
}