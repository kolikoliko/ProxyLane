#include "stdafx.h"
#include "ProxyLane.h"
#include "LaunchPanel.h"
#include "ModernUI.h"

namespace
{
	const int kPadding = 16;
	const int kHeaderHeight = 88;
	const int kIconBox = 44;
	const int kTileWidth = 156;
	const int kTileHeight = 40;
	const int kTileGap = 8;
	const int kTileIcon = 24;
	const int kRecentLabelTop = 98;
	const int kTileTop = 120;
}

IMPLEMENT_DYNAMIC(CLaunchPanel, CWnd)

BEGIN_MESSAGE_MAP(CLaunchPanel, CWnd)
	ON_WM_PAINT()
	ON_WM_ERASEBKGND()
	ON_WM_SIZE()
	ON_WM_MOUSEMOVE()
	ON_MESSAGE(WM_MOUSELEAVE, OnMouseLeave)
	ON_WM_LBUTTONDOWN()
	ON_WM_LBUTTONUP()
	ON_WM_KEYDOWN()
	ON_WM_SETFOCUS()
	ON_WM_KILLFOCUS()
	ON_WM_GETDLGCODE()
	ON_WM_DESTROY()
END_MESSAGE_MAP()

CLaunchPanel::CLaunchPanel()
	: m_enabled(FALSE)
	, m_hot(-1)
	, m_pressed(-1)
	, m_focusTile(0)
	, m_tracking(FALSE)
	, m_fontDpi(0)
	, m_actionWidth(0)
{
}

CLaunchPanel::~CLaunchPanel()
{
}

BOOL CLaunchPanel::Create(CWnd* parent, UINT id)
{
	CString className = AfxRegisterWndClass(CS_HREDRAW | CS_VREDRAW,
		::LoadCursor(NULL, IDC_ARROW), NULL, NULL);
	if (!CWnd::Create(className, _T(""),
		WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS,
		CRect(0, 0, 0, 0), parent, id))
		return FALSE;
	if (m_tooltip.Create(this, TTS_ALWAYSTIP | TTS_NOPREFIX))
	{
		m_tooltip.AddTool(this, LPSTR_TEXTCALLBACK);
		m_tooltip.SetMaxTipWidth(Scale(480));
		m_tooltip.SetDelayTime(TTDT_AUTOPOP, 30000);
	}
	return TRUE;
}

void CLaunchPanel::OnDestroy()
{
	CWnd::OnDestroy();
}

int CLaunchPanel::Scale(int value) const
{
	return UiTheme::ScaleForWindow(m_hWnd, value);
}

void CLaunchPanel::EnsureFonts()
{
	HDC dc = ::GetDC(m_hWnd);
	const int dpi = dc ? ::GetDeviceCaps(dc, LOGPIXELSY) : 96;
	if (dc) ::ReleaseDC(m_hWnd, dc);
	if (m_fontDpi == dpi && m_titleFont.GetSafeHandle()) return;
	m_fontDpi = dpi;
	UiTheme::CreateUiFont(m_titleFont, m_hWnd, 11, FW_SEMIBOLD);
	UiTheme::CreateUiFont(m_bodyFont, m_hWnd, 9, FW_NORMAL);
	UiTheme::CreateUiFont(m_labelFont, m_hWnd, 9, FW_SEMIBOLD);
}

void CLaunchPanel::SetText(const CString& title, const CString& body,
	const CString& recentTitle, const CString& emptyText)
{
	if (m_title == title && m_body == body && m_recentTitle == recentTitle && m_emptyText == emptyText)
		return;
	m_title = title;
	m_body = body;
	m_recentTitle = recentTitle;
	m_emptyText = emptyText;
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::SetActionWidth(int width)
{
	if (m_actionWidth == width) return;
	m_actionWidth = width;
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::SetEnabledState(BOOL enabled)
{
	if (m_enabled == enabled) return;
	m_enabled = enabled;
	SetHotTile(-1);
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::SetTiles(const std::vector<Tile>& tiles)
{
	m_tiles = tiles;
	if (m_focusTile >= static_cast<int>(m_tiles.size())) m_focusTile = 0;
	m_hot = -1;
	m_pressed = -1;
	m_tipText.Empty();
	if (m_tooltip.GetSafeHwnd()) m_tooltip.Pop();
	if (GetSafeHwnd()) Invalidate(FALSE);
}

int CLaunchPanel::PreferredHeight() const
{
	return Scale(kTileTop + kTileHeight + kPadding);
}

CRect CLaunchPanel::ActionSlot(int buttonWidth, int buttonHeight) const
{
	CRect client;
	GetClientRect(&client);
	const int top = (Scale(kHeaderHeight) - buttonHeight) / 2;
	return CRect(client.right - Scale(kPadding) - buttonWidth, top,
		client.right - Scale(kPadding), top + buttonHeight);
}

CRect CLaunchPanel::HeaderTextRect() const
{
	CRect client;
	GetClientRect(&client);
	const int left = Scale(kPadding + kIconBox + 14);
	return CRect(left, Scale(20),
		max(left, client.right - Scale(kPadding) - m_actionWidth - Scale(20)),
		Scale(kHeaderHeight - 8));
}

int CLaunchPanel::VisibleTileCount() const
{
	CRect client;
	GetClientRect(&client);
	const int slot = Scale(kTileWidth + kTileGap);
	const int fit = max(1, (client.Width() - Scale(kPadding) * 2 + Scale(kTileGap)) / max(1, slot));
	return min(static_cast<int>(m_tiles.size()), fit);
}

CRect CLaunchPanel::TileRect(int index) const
{
	const int left = Scale(kPadding) + index * Scale(kTileWidth + kTileGap);
	return CRect(left, Scale(kTileTop), left + Scale(kTileWidth), Scale(kTileTop + kTileHeight));
}

int CLaunchPanel::HitTestTile(CPoint point) const
{
	const int count = VisibleTileCount();
	for (int i = 0; i < count; ++i)
		if (TileRect(i).PtInRect(point)) return i;
	return -1;
}

void CLaunchPanel::SetHotTile(int index)
{
	if (m_hot == index) return;
	m_hot = index;
	if (GetSafeHwnd()) Invalidate(FALSE);
}

void CLaunchPanel::ActivateTile(int index)
{
	if (!m_enabled || index < 0 || index >= VisibleTileCount()) return;
	if (CWnd* parent = GetParent())
		parent->SendMessage(WM_LAUNCH_PANEL_TILE, static_cast<WPARAM>(index), 0);
}

BOOL CLaunchPanel::OnEraseBkgnd(CDC*)
{
	return TRUE;
}

void CLaunchPanel::OnSize(UINT type, int cx, int cy)
{
	CWnd::OnSize(type, cx, cy);
	Invalidate(FALSE);
}

void CLaunchPanel::OnPaint()
{
	EnsureFonts();
	CPaintDC paint(this);
	CRect client;
	GetClientRect(&client);
	if (client.IsRectEmpty()) return;

	CDC dc;
	CBitmap bitmap;
	dc.CreateCompatibleDC(&paint);
	bitmap.CreateCompatibleBitmap(&paint, client.Width(), client.Height());
	CBitmap* oldBitmap = dc.SelectObject(&bitmap);

	// Page background first so the rounded corners blend into the page.
	dc.FillSolidRect(client, UiTheme::PageBackground());
	{
		CRect card = client;
		card.DeflateRect(0, 0, 1, 1);
		CPen pen(PS_SOLID, 1, UiTheme::Border());
		CBrush brush(UiTheme::Surface());
		CPen* oldPen = dc.SelectObject(&pen);
		CBrush* oldBrush = dc.SelectObject(&brush);
		dc.RoundRect(card, CPoint(Scale(10), Scale(10)));
		dc.SelectObject(oldBrush);
		dc.SelectObject(oldPen);
	}

	dc.SetBkMode(TRANSPARENT);
	const COLORREF primary = m_enabled ? UiTheme::TextPrimary() : UiTheme::TextSecondary();

	// Header glyph: a tray with a downward arrow.
	{
		CRect box(Scale(kPadding), Scale(20), Scale(kPadding + kIconBox), Scale(20 + kIconBox));
		CPen pen(PS_SOLID, 1, m_enabled ? UiTheme::AccentSoftBorder() : UiTheme::Border());
		CBrush brush(m_enabled ? UiTheme::AccentSoft() : RGB(240, 242, 245));
		CPen* oldPen = dc.SelectObject(&pen);
		CBrush* oldBrush = dc.SelectObject(&brush);
		dc.RoundRect(box, CPoint(Scale(10), Scale(10)));
		dc.SelectObject(oldBrush);
		dc.SelectObject(oldPen);

		const COLORREF ink = m_enabled ? UiTheme::Accent() : RGB(160, 166, 177);
		CPen ink2(PS_SOLID, max(2, Scale(2)), ink);
		oldPen = dc.SelectObject(&ink2);
		const int cx = box.CenterPoint().x;
		const int top = box.top + Scale(10);
		const int tip = box.top + Scale(24);
		const int wing = Scale(6);
		dc.MoveTo(cx, top);
		dc.LineTo(cx, tip);
		dc.MoveTo(cx - wing, tip - wing);
		dc.LineTo(cx, tip);
		dc.LineTo(cx + wing, tip - wing);
		dc.MoveTo(box.left + Scale(11), box.bottom - Scale(11));
		dc.LineTo(box.right - Scale(11), box.bottom - Scale(11));
		dc.SelectObject(oldPen);
	}

	// Header title and body.
	{
		CRect text = HeaderTextRect();
		CFont* oldFont = dc.SelectObject(&m_titleFont);
		dc.SetTextColor(primary);
		CRect titleRect(text.left, text.top, text.right, text.top + Scale(24));
		dc.DrawText(m_title, titleRect, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS | DT_NOPREFIX);
		dc.SelectObject(&m_bodyFont);
		dc.SetTextColor(UiTheme::TextSecondary());
		CRect bodyRect(text.left, titleRect.bottom + Scale(2), text.right, text.bottom);
		dc.DrawText(m_body, bodyRect, DT_LEFT | DT_WORDBREAK | DT_END_ELLIPSIS | DT_NOPREFIX);
		dc.SelectObject(oldFont);
	}

	// Divider between the header and the recent apps.
	dc.FillSolidRect(Scale(kPadding), Scale(kHeaderHeight), client.Width() - Scale(kPadding) * 2, 1, UiTheme::Border());

	// Recent apps.
	{
		CFont* oldFont = dc.SelectObject(&m_labelFont);
		dc.SetTextColor(UiTheme::TextSecondary());
		CRect label(Scale(kPadding), Scale(kRecentLabelTop), client.right - Scale(kPadding), Scale(kRecentLabelTop + 20));
		dc.DrawText(m_recentTitle, label, DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_NOPREFIX);

		const int count = VisibleTileCount();
		if (count == 0)
		{
			dc.SelectObject(&m_bodyFont);
			CRect empty(Scale(kPadding), Scale(kTileTop), client.right - Scale(kPadding), Scale(kTileTop + kTileHeight));
			dc.DrawText(m_emptyText, empty, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
		}
		dc.SelectObject(&m_bodyFont);
		for (int i = 0; i < count; ++i)
		{
			CRect tile = TileRect(i);
			const BOOL hot = m_enabled && i == m_hot;
			const BOOL down = hot && i == m_pressed;
			CPen pen(PS_SOLID, 1, hot ? UiTheme::Accent() : UiTheme::Border());
			CBrush brush(down ? UiTheme::AccentSoft() : (hot ? RGB(246, 249, 254) : RGB(255, 255, 255)));
			CPen* oldPen = dc.SelectObject(&pen);
			CBrush* oldBrush = dc.SelectObject(&brush);
			CRect body = tile;
			body.DeflateRect(0, 0, 1, 1);
			dc.RoundRect(body, CPoint(Scale(8), Scale(8)));
			dc.SelectObject(oldBrush);
			dc.SelectObject(oldPen);

			const int iconSize = Scale(kTileIcon);
			const int iconLeft = tile.left + Scale(10);
			const int iconTop = tile.top + (tile.Height() - iconSize) / 2;
			if (m_tiles[i].icon)
				::DrawIconEx(dc.m_hDC, iconLeft, iconTop, m_tiles[i].icon, iconSize, iconSize, 0, NULL, DI_NORMAL);
			dc.SetTextColor(m_enabled ? UiTheme::TextPrimary() : UiTheme::TextSecondary());
			CRect name(iconLeft + iconSize + Scale(8), tile.top, tile.right - Scale(10), tile.bottom);
			dc.DrawText(m_tiles[i].name, name, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);

			if (m_enabled && ::GetFocus() == m_hWnd && i == m_focusTile)
			{
				CRect focus = tile;
				focus.DeflateRect(Scale(3), Scale(3));
				dc.DrawFocusRect(focus);
			}
		}
		dc.SelectObject(oldFont);
	}

	paint.BitBlt(0, 0, client.Width(), client.Height(), &dc, 0, 0, SRCCOPY);
	dc.SelectObject(oldBitmap);
}

void CLaunchPanel::OnMouseMove(UINT flags, CPoint point)
{
	if (!m_tracking)
	{
		TRACKMOUSEEVENT track = { sizeof(track), TME_LEAVE, m_hWnd, 0 };
		m_tracking = _TrackMouseEvent(&track);
	}
	const int hit = HitTestTile(point);
	SetHotTile(hit);
	CString tip = (hit >= 0 && hit < static_cast<int>(m_tiles.size())) ? m_tiles[hit].tip : CString();
	if (tip != m_tipText)
	{
		if (m_tooltip.GetSafeHwnd()) m_tooltip.Pop();
		m_tipText = tip;
	}
	::SetCursor(::LoadCursor(NULL, m_enabled && hit >= 0 ? IDC_HAND : IDC_ARROW));
	CWnd::OnMouseMove(flags, point);
}

LRESULT CLaunchPanel::OnMouseLeave(WPARAM, LPARAM)
{
	m_tracking = FALSE;
	SetHotTile(-1);
	return 0;
}

void CLaunchPanel::OnLButtonDown(UINT flags, CPoint point)
{
	SetFocus();
	const int hit = HitTestTile(point);
	if (m_enabled && hit >= 0)
	{
		m_pressed = hit;
		m_focusTile = hit;
		SetCapture();
		Invalidate(FALSE);
	}
	CWnd::OnLButtonDown(flags, point);
}

void CLaunchPanel::OnLButtonUp(UINT flags, CPoint point)
{
	const int pressed = m_pressed;
	if (GetCapture() == this) ReleaseCapture();
	m_pressed = -1;
	Invalidate(FALSE);
	if (pressed >= 0 && HitTestTile(point) == pressed)
		ActivateTile(pressed);
	CWnd::OnLButtonUp(flags, point);
}

void CLaunchPanel::OnKeyDown(UINT character, UINT repeatCount, UINT flags)
{
	const int count = VisibleTileCount();
	if (count > 0)
	{
		switch (character)
		{
		case VK_LEFT: m_focusTile = max(0, m_focusTile - 1); Invalidate(FALSE); return;
		case VK_RIGHT: m_focusTile = min(count - 1, m_focusTile + 1); Invalidate(FALSE); return;
		case VK_HOME: m_focusTile = 0; Invalidate(FALSE); return;
		case VK_END: m_focusTile = count - 1; Invalidate(FALSE); return;
		case VK_RETURN:
		case VK_SPACE: ActivateTile(m_focusTile); return;
		}
	}
	CWnd::OnKeyDown(character, repeatCount, flags);
}

void CLaunchPanel::OnSetFocus(CWnd* oldWindow)
{
	CWnd::OnSetFocus(oldWindow);
	Invalidate(FALSE);
}

void CLaunchPanel::OnKillFocus(CWnd* newWindow)
{
	CWnd::OnKillFocus(newWindow);
	Invalidate(FALSE);
}

UINT CLaunchPanel::OnGetDlgCode()
{
	return DLGC_WANTARROWS | DLGC_WANTCHARS;
}

BOOL CLaunchPanel::PreTranslateMessage(MSG* message)
{
	if (m_tooltip.GetSafeHwnd())
	{
		m_tooltip.Activate(!m_tipText.IsEmpty());
		m_tooltip.RelayEvent(message);
	}
	return CWnd::PreTranslateMessage(message);
}

BOOL CLaunchPanel::OnNotify(WPARAM wParam, LPARAM lParam, LRESULT* result)
{
	NMHDR* header = reinterpret_cast<NMHDR*>(lParam);
	if (header && m_tooltip.GetSafeHwnd() && header->hwndFrom == m_tooltip.GetSafeHwnd() &&
		header->code == TTN_NEEDTEXT)
	{
		reinterpret_cast<NMTTDISPINFO*>(header)->lpszText = const_cast<LPTSTR>(static_cast<LPCTSTR>(m_tipText));
		*result = 0;
		return TRUE;
	}
	return CWnd::OnNotify(wParam, lParam, result);
}
