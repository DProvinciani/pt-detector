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

	const TestCommon::ExecutorsMode GetMode()
	{
		return m_testExecutorMode;
	}

	Executor(std::wstring description, TestCommon::ExecutorsMode mode) :
		m_description(description), m_testExecutorMode(mode) {}

	Executor() :
		m_description(L""), m_testExecutorMode(TestCommon::ExecutorsMode::NA) {}

private:
	std::wstring m_description;
	TestCommon::ExecutorsMode m_testExecutorMode;
};

#endif

