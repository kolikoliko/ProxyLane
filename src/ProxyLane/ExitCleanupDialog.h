#pragma once
#include "ExitProcessesDialog.h"
#include "ExitProcessCleanup.h"
#include "Page3.h"
#include <afxcmn.h>

// Confirmation, cleanup and timeout share this one window. The worker never
// touches controls; its result is read only after its thread has finished.
class CExitCleanupDialog : public CExitProcessesDialog
{
public:
	CExitCleanupDialog(CPage3* page, UINT count, const CString& processes, CWnd* parent)
		: CExitProcessesDialog(count, processes, parent), m_page(page) {}
	~CExitCleanupDialog()
	{
		if (m_worker)
		{
			SetEvent(m_cancel);
			WaitForSingleObject(m_worker->m_hThread, INFINITE);
			delete m_worker;
		}
		if (m_cancel) CloseHandle(m_cancel);
	}

	ExitProcessCleanup::Result<_myPROCESSINFO> result;
	DWORD workerError = ERROR_SUCCESS;

protected:
	BOOL OnInitDialog() override
	{
		CExitProcessesDialog::OnInitDialog();
		CRect area;
		GetDlgItem(IDC_EXIT_WARNING)->GetWindowRect(&area);
		ScreenToClient(&area);
		const int barHeight = UiTheme::ScaleForWindow(m_hWnd, 4);
		CClientDC dc(this);
		CFont* oldFont = dc.SelectObject(&m_uiFont);
		TEXTMETRIC metrics = {};
		dc.GetTextMetrics(&metrics);
		dc.SelectObject(oldFont);
		area.top = min(area.bottom - barHeight,
			area.top + metrics.tmHeight + UiTheme::ScaleForWindow(m_hWnd, 8));
		area.bottom = area.top + barHeight;
		area.right = area.left + UiTheme::ScaleForWindow(m_hWnd, 96);
		m_progress.Create(WS_CHILD | PBS_MARQUEE, area, this, IDC_EXIT_PROGRESS);
		return FALSE;
	}
	void OnOK() override
	{
		if (!m_worker) EndDialog(IDOK);
	}
	void OnCancel() override
	{
		if (!m_worker) { EndDialog(IDCANCEL); return; }
		SetEvent(m_cancel);
		GetDlgItem(IDCANCEL)->EnableWindow(FALSE);
		if (m_slowShown)
			SetDlgItemText(IDC_EXIT_WARNING, Localization::Get(_T("exit.stopping")));
	}
	BOOL OnCommand(WPARAM wParam, LPARAM lParam) override
	{
		if (LOWORD(wParam) == IDC_EXIT_TERMINATE && HIWORD(wParam) == BN_CLICKED)
		{
			if (!m_worker) StartCleanup();
			return TRUE;
		}
		return CModernDialog::OnCommand(wParam, lParam);
	}
	LRESULT WindowProc(UINT message, WPARAM wParam, LPARAM lParam) override
	{
		if (message == WM_TIMER && wParam == 1 && m_worker)
		{
			if (WaitForSingleObject(m_worker->m_hThread, 0) == WAIT_OBJECT_0)
				FinishCleanup();
			else if (!m_slowShown && GetTickCount() - m_started >= 500 &&
				WaitForSingleObject(m_cancel, 0) != WAIT_OBJECT_0 &&
				InterlockedCompareExchange(&m_hasProcesses, 0, 0))
			{
				// Do not flash a status just for the final quiet-period checks
				// after all processes have already exited.
				m_slowShown = true;
				SetDlgItemText(IDC_EXIT_WARNING, Localization::Get(_T("exit.cleaning")));
				SetDlgItemText(IDCANCEL, Localization::Get(_T("exit.stop_cleanup")));
				if (m_progress.GetSafeHwnd())
				{
					m_progress.SendMessage(PBM_SETMARQUEE, TRUE, 40);
					m_progress.ShowWindow(SW_SHOW);
				}
			}
			return 0;
		}
		return CExitProcessesDialog::WindowProc(message, wParam, lParam);
	}

private:
	void StartCleanup()
	{
		GetDlgItem(IDOK)->EnableWindow(FALSE);
		GetDlgItem(IDC_EXIT_TERMINATE)->EnableWindow(FALSE);
		SetDefID(IDCANCEL);
		GetDlgItem(IDCANCEL)->SetFocus();
		result = ExitProcessCleanup::Result<_myPROCESSINFO>();
		workerError = ERROR_SUCCESS;
		m_slowShown = false;
		InterlockedExchange(&m_hasProcesses, 1);
		if (!m_cancel) m_cancel = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!m_cancel)
		{ workerError = GetLastError(); EndDialog(IDABORT); return; }
		ResetEvent(m_cancel);
		m_started = GetTickCount();
		if (!SetTimer(1, 50, NULL))
		{ workerError = ERROR_NOT_ENOUGH_MEMORY; EndDialog(IDABORT); return; }
		m_worker = AfxBeginThread(Work, this, THREAD_PRIORITY_NORMAL, 0, CREATE_SUSPENDED);
		if (!m_worker)
		{ workerError = ERROR_NOT_ENOUGH_MEMORY; EndDialog(IDABORT); return; }
		m_worker->m_bAutoDelete = FALSE;
		m_worker->ResumeThread();
	}
	void FinishCleanup()
	{
		KillTimer(1);
		delete m_worker;
		m_worker = NULL;
		if (m_progress.GetSafeHwnd())
		{
			m_progress.SendMessage(PBM_SETMARQUEE, FALSE, 0);
			m_progress.ShowWindow(SW_HIDE);
		}
		if (result.status == ExitProcessCleanup::TimedOut)
		{
			CString remaining;
			for (size_t i = 0; i < result.processes.size(); ++i)
			{
				CString line;
				line.Format(_T("%s  (PID %lu)\r\n"), result.processes[i].proname, result.processes[i].pid);
				remaining += line;
			}
			UpdateProcesses(static_cast<UINT>(result.processes.size()), remaining);
			SetDlgItemText(IDC_EXIT_WARNING, Localization::Format(_T("exit.timeout"),
				static_cast<UINT>(result.processes.size())));
			SetDlgItemText(IDC_EXIT_TERMINATE, Localization::Get(_T("exit.continue")));
			SetDlgItemText(IDCANCEL, Localization::Get(_T("exit.return")));
			GetDlgItem(IDOK)->EnableWindow(TRUE);
			GetDlgItem(IDCANCEL)->EnableWindow(TRUE);
			GetDlgItem(IDC_EXIT_TERMINATE)->EnableWindow(TRUE);
			SetDefID(IDCANCEL);
			GetDlgItem(IDCANCEL)->SetFocus();
			return;
		}
		EndDialog(result.status == ExitProcessCleanup::Completed ? IDOK :
			(result.status == ExitProcessCleanup::Cancelled ? IDCANCEL : IDABORT));
	}
	static UINT Work(LPVOID context)
	{
		CExitCleanupDialog* self = static_cast<CExitCleanupDialog*>(context);
		try
		{
			self->result = ExitProcessCleanup::Run<_myPROCESSINFO>(
				[self](std::vector<_myPROCESSINFO>& processes) {
					self->m_page->GetRunningHookedProcesses(processes);
					InterlockedExchange(&self->m_hasProcesses, processes.empty() ? 0 : 1);
				}, self->m_cancel);
		}
		catch (...)
		{ self->workerError = ERROR_NOT_ENOUGH_MEMORY; self->result.status = ExitProcessCleanup::Failed; }
		return 0;
	}
	CPage3* m_page;
	CWinThread* m_worker = NULL;
	HANDLE m_cancel = NULL;
	DWORD m_started = 0;
	volatile LONG m_hasProcesses = 0;
	bool m_slowShown = false;
	CProgressCtrl m_progress;
};
