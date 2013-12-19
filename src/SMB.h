/*
 *      Copyright (C) 2005-2013 Team XBMC
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */
#pragma once

#include <xbmc/threads/mutex.h>
#include <string>

#define NT_STATUS_CONNECTION_REFUSED long(0xC0000000 | 0x0236)
#define NT_STATUS_INVALID_HANDLE long(0xC0000000 | 0x0008)
#define NT_STATUS_ACCESS_DENIED long(0xC0000000 | 0x0022)
#define NT_STATUS_OBJECT_NAME_NOT_FOUND long(0xC0000000 | 0x0034)
#define NT_STATUS_INVALID_COMPUTER_NAME long(0xC0000000 | 0x0122)

struct _SMBCCTX;
typedef _SMBCCTX SMBCCTX;

class CSMB2 : public PLATFORM::CMutex
{
public:
  static CSMB2& Get();
  void Init();
  void Deinit();
  void Purge();
  void PurgeEx(const std::string& hostname, const std::string& filename);
  void CheckIfIdle();
  void SetActivityTime();
  void AddActiveConnection();
  void AddIdleConnection();
  std::string URLEncode(const std::string& domain, 
                        const std::string& hostname, const std::string& filename,
                        const std::string& username, const std::string& password);

  int32_t ConvertUnixToNT(int error);
protected:
  CSMB2();
  virtual ~CSMB2();

  SMBCCTX *m_context;
  std::string m_strLastHost;
  std::string m_strLastShare;
  int m_OpenConnections;
  unsigned int m_IdleTimeout;
};
