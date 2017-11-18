#ifndef _EXECUTOR_H_
#define _EXECUTOR_H_

#include "helpers.h"

class Executor
{

public:
	virtual bool Execute(TestCommon::TestData &data) = 0;

	const std::wstring GetDescription()
	{
		return m_description;
	}

	const TestCommon::TestExecutorsMode GetMode()
	{
		return m_testExecutorMode;
	}

	Executor(std::wstring description, TestCommon::TestExecutorsMode mode) :
		m_description(description), m_testExecutorMode(mode) {}

	Executor() :
		m_description(L""), m_testExecutorMode(TestCommon::TestExecutorsMode::TEST_NA) {}

private:
	std::wstring m_description;
	TestCommon::TestExecutorsMode m_testExecutorMode;
};

#endif

