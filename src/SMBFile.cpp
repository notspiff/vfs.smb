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

#include "xbmc/libXBMC_addon.h"
#include "xbmc/threads/mutex.h"
#include <fcntl.h>
#include <map>
#include <sstream>

#include "SMB.h"

ADDON::CHelper_libXBMC_addon *XBMC           = NULL;

extern "C" {

#include "xbmc/xbmc_vfs_dll.h"
#include "xbmc/IFileTypes.h"

//-- Create -------------------------------------------------------------------
// Called on load. Addon should fully initalize or return error status
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_Create(void* hdl, void* props)
{
  if (!XBMC)
    XBMC = new ADDON::CHelper_libXBMC_addon;

  if (!XBMC->RegisterMe(hdl))
  {
    delete XBMC, XBMC=NULL;
    return ADDON_STATUS_PERMANENT_FAILURE;
  }

  return ADDON_STATUS_OK;
}

//-- Stop ---------------------------------------------------------------------
// This dll must cease all runtime activities
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Stop()
{
}

//-- Destroy ------------------------------------------------------------------
// Do everything before unload of this add-on
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Destroy()
{
  XBMC=NULL;
}

//-- HasSettings --------------------------------------------------------------
// Returns true if this add-on use settings
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
bool ADDON_HasSettings()
{
  return false;
}

//-- GetStatus ---------------------------------------------------------------
// Returns the current Status of this visualisation
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_GetStatus()
{
  return ADDON_STATUS_OK;
}

//-- GetSettings --------------------------------------------------------------
// Return the settings for XBMC to display
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
unsigned int ADDON_GetSettings(ADDON_StructSetting ***sSet)
{
  return 0;
}

//-- FreeSettings --------------------------------------------------------------
// Free the settings struct passed from XBMC
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------

void ADDON_FreeSettings()
{
}

//-- SetSetting ---------------------------------------------------------------
// Set a specific Setting value (called from XBMC)
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
ADDON_STATUS ADDON_SetSetting(const char *strSetting, const void* value)
{
  return ADDON_STATUS_OK;
}

//-- Announce -----------------------------------------------------------------
// Receive announcements from XBMC
// !!! Add-on master function !!!
//-----------------------------------------------------------------------------
void ADDON_Announce(const char *flag, const char *sender, const char *message, const void *data)
{
}

struct SMBContext
{
  int fd;
  int size;

  SMBContext()
  {
    fd = -1;
    size = 0;
  }
};

static std::string GetAuthenticatedPath(VFSURL* url)
{
  bool res = XBMC->AuthenticateURL(url);
  std::string result = CSMB::Get().URLEncode(url->domain, url->hostname, url->filename, url->username, url->password);
  if (res)
  {
    XBMC->FreeString(url->username);
    XBMC->FreeString(url->password);
  }
  return result;
}

void* Open(VFSURL* url)
{
  CSMB::Get().Init();
  CSMB::Get().AddActiveConnection();

}

bool Close(void* context)
{
  SMBContext* ctx = (SMBContext*)context;
  XBMC->Log(ADDON::LOG_DEBUG,"CSmbFile::Close closing fd %d", ctx->fd);
  PLATFORM::CLockObject lock(CSMB::Get());
  smbc_close(ctx->fd);
  CSMB::Get().AddIdleConnection();
}

unsigned int Read(void* context, void* lpBuf, int64_t uiBufSize)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return 0;

  PLATFORM::CLockObject lock(CSMB::Get()); // Init not called since it has to be "inited" by now
  CSMB::Get().SetActivityTime();
  /* work around stupid bug in samba */
  /* some samba servers has a bug in it where the */
  /* 17th bit will be ignored in a request of data */
  /* this can lead to a very small return of data */
  /* also worse, a request of exactly 64k will return */
  /* as if eof, client has a workaround for windows */
  /* thou it seems other servers are affected too */
  if( uiBufSize >= 64*1024-2 )
    uiBufSize = 64*1024-2;

  int bytesRead = smbc_read(ctx->fd, lpBuf, (int)uiBufSize);

  if ( bytesRead < 0 && errno == EINVAL )
  {
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %d, %d, %s ) - Retrying", __FUNCTION__, bytesRead, errno, strerror(errno));
    bytesRead = smbc_read(ctx->fd, lpBuf, (int)uiBufSize);
  }

  if ( bytesRead < 0 )
  {
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %d, %d, %s )", __FUNCTION__, bytesRead, errno, strerror(errno));
    return 0;
  }

  return (unsigned int)bytesRead;
}

int64_t GetLength(void* context)
{
  SMBContext* ctx = (SMBContext*)context;

  return ctx->size;
}

int64_t GetPosition(void* context)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return 0;
  CSMB::Get().Init();
  PLATFORM::CLockObject lock(CSMB::Get());
  int64_t pos = smbc_lseek(ctx->fd, 0, SEEK_CUR);
  if ( pos < 0 )
    return 0;
  return pos;
}

int64_t Seek(void* context, int64_t iFilePosition, int iWhence)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return -1;

  PLATFORM::ClockObject lock(CSMB::Get()); // Init not called since it has to be "inited" by now
  CSMB::Get().SetActivityTime();
  int64_t pos = smbc_lseek(ctx->fd, iFilePosition, iWhence);

  if ( pos < 0 )
  {
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %"PRId64", %d, %s )", __FUNCTION__, pos, errno, strerror(errno));
    return -1;
  }

  return (int64_t)pos;
}

static bool IsValidFile(const std::string& strFileName)
{
  if (strFileName.find('/') == std::string::npos || /* doesn't have sharename */
      strFileName.substr(strFileName.size()-2) == "/." || /* not current folder */
      strFileName.substr(strFileName.size()-3) == "/..")  /* not parent folder */
    return false;
  return true;
}

bool Exists(VFSURL* url)
{
  // we can't open files like smb://file.f or smb://server/file.f
  // if a file matches the if below return false, it can't exist on a samba share.
  if (!IsValidFile(url.filename))
    return false;

  CSMB::Get().Init();
  std::string strFileName = GetAuthenticatedPath(url);

  struct stat info;

  PLATFORM::CLockObject lock(CSMB::Get());
  int iResult = smbc_stat(strFileName.c_str(), &info);

  if (iResult < 0)
    return false;

  return true;
}

int Stat(const char* url, const char* hostname,
         const char* filename2, unsigned int port,
         const char* options, const char* username,
         const char* password, struct __stat64* buffer)
{
  CSMB::Get().Init();
  std::string strFileName = GetAuthenticatedPath(url);
  PLATFORM::CLockObject lock(CSMB::Get());

  struct stat tmpBuffer = {0};
  int iResult = smbc_stat(strFileName.c_str(), &tmpBuffer);

  memset(buffer, 0, sizeof(struct __stat64));
  buffer->st_dev = tmpBuffer.st_dev;
  buffer->st_ino = tmpBuffer.st_ino;
  buffer->st_mode = tmpBuffer.st_mode;
  buffer->st_nlink = tmpBuffer.st_nlink;
  buffer->st_uid = tmpBuffer.st_uid;
  buffer->st_gid = tmpBuffer.st_gid;
  buffer->st_rdev = tmpBuffer.st_rdev;
  buffer->st_size = tmpBuffer.st_size;
  buffer->st_atime = tmpBuffer.st_atime;
  buffer->st_mtime = tmpBuffer.st_mtime;
  buffer->st_ctime = tmpBuffer.st_ctime;

  return iResult;
}

int IoControl(void* context, XFILE::EIoControl request, void* param)
{
  return -1;
}

void ClearOutIdle()
{
  CSMB::Get().CheckIfIdle();
}

void DisconnectAll()
{
  CSMB::Get().Deinit();
}

bool DirectoryExists(const char* url, const char* hostname,
                     const char* filename, unsigned int port,
                     const char* options, const char* username,
                     const char* password)
{
  PLATFORM::CLockObject lock(CSMB::Get());
  CSMB::Get().Init();

  if (!XBMC->AuthenticateURL(url))
    return false;

  std::string strFileName = CSMB::Get().URLEncode(domain, hostname, filename,
                                                  username, password);

  struct stat info;
  if (smbc_stat(strFileName.c_str(), &info) != 0)
    return false;

  return (info.st_mode & S_IFDIR) ? true : false;
}

void* GetDirectory(const char* url, const char* hostname,
                   const char* filename, unsigned int port,
                   const char* options, const char* username,
                   const char* password, VFSDirEntry** items,
                   int* num_items)
{
}

void FreeDirectory(void* items)
{
}

bool CreateDirectory(const char* url, const char* hostname,
                     const char* filename, unsigned int port,
                     const char* options, const char* username,
                     const char* password)
{
  bool success = true;
  PLATFORM::CLockObject lock(CSMB::Get());
  CSMB::Get().Init();

  if (!XBMC->AuthenticateURL(url))
    return false;

  std::string strFileName = CSMB::Get().URLEncode(domain, hostname, filename,
                                                  username, password);

  int result = smbc_mkdir(strFileName.c_str(), 0);
  success = (result == 0 || EEXIST == errno);
  if(!success)
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return success;
}

bool RemoveDirectory(const char* url, const char* hostname,
                     const char* filename, unsigned int port,
                     const char* options, const char* username,
                     const char* password)
{
  PLATFORM::CLockObject lock(CSMB::Get());
  CSMB::Get().Init();

  if (!XBMC->AuthenticateURL(url))
    return false;

  std::string strFileName = CSMB::Get().URLEncode(domain, hostname,
                                                  filename, username, password);

  int result = smbc_rmdir(strFileName.c_str());

  if(result != 0 && errno != ENOENT)
  {
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));
    return false;
  }

  return true;
}

int Truncate(void* context, int64_t size)
{
/* 
 * This would force us to be dependant on SMBv3.2 which is GPLv3
 * This is only used by the TagLib writers, which are not currently in use
 * So log and warn until we implement TagLib writing & can re-implement this better.
  CSingleLock lock(smb); // Init not called since it has to be "inited" by now

#if defined(TARGET_ANDROID)
  int iResult = 0;
#else
  int iResult = smbc_ftruncate(m_fd, size);
#endif
*/
  XBMC->Log(ADDON::LOG_ERROR, "%s - Warning(smbc_ftruncate called and not implemented)", __FUNCTION__);
  return 0;
}

int Write(void* context, const void* lpBuf, int64_t uiBufSize)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return -1;

  int dwNumberOfBytesWritten = 0;

  // lpBuf can be safely casted to void* since xmbc_write will only read from it.
  CSMB::Get().Init();
  PLATFORM::CLockObject lock(CSMB::Get());
  dwNumberOfBytesWritten = smbc_write(m_fd, (void*)lpBuf, uiBufSize);

  return (int)dwNumberOfBytesWritten;
}

bool Delete(const char* url, const char* hostname,
            const char* filename, unsigned int port,
            const char* options, const char* username,
            const char* password)
{
  CSMB::Get().Init();
  std::string strFile = GetAuthenticatedPath(domain, hostname,
                                             filename, username, password);

  PLATFORM::CLockObject lock(CSMB::Get());

  int result = smbc_unlink(strFile.c_str());

  if(result != 0)
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return (result == 0);
}

bool Rename(const char* url, const char* hostname,
            const char* filename, unsigned int port,
            const char* options, const char* username,
            const char* password,
            const char* url2, const char* hostname2,
            const char* filename2, unsigned int port2,
            const char* options2, const char* username2,
            const char* password2)
{
  CSMB::Get().Init();
  std::string strFile = GetAuthenticatedPath(domain, hostname,
                                             filename, username, password);
  std::string strFileNew = GetAuthenticatedPath(domain2, hostname2, filename2,
                                               username2, password2);
  PLATFORM::CLockObject lock(CSMB::Get());

  int result = smbc_rename(strFile.c_str(), strFileNew.c_str());

  if(result != 0)
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return (result == 0);
}

void* OpenForWrite(const char* url, const char* hostname,
                   const char* filename, unsigned int port,
                   const char* options, const char* username,
                   const char* password, bool bOverWrite)
{ 
  CSMB::Get().Init();
  // we can't open files like smb://file.f or smb://server/file.f
  // if a file matches the if below return false, it can't exist on a samba share.
  if (!IsValidFile(filename))
    return NULL;

  std::string strFileName = GetAuthenticatedPath(domain, hostname,
                                                 filename, username, password);
  PLATFORM::CLockObject lock(CSMB::Get());

  SMBContext* result = new SMBContext;
  if (bOverWrite)
  {
    XBMC->Log(ADDON::LOG_INFO, "FileSmb::OpenForWrite() called with overwriting enabled! - %s", strFileName.c_str());
    result->fd = smbc_creat(strFileName.c_str(), 0);
  }
  else
  {
    result->fd = smbc_open(strFileName.c_str(), O_RDWR, 0);
  }

  if (result->fd == -1)
  {
    // write error to logfile
    XBMC->Log(ADDON::LOG_ERROR, "FileSmb->Open: Unable to open file : '%s'\nunix_err:'%x' error : '%s'", strFileName.c_str(), errno, strerror(errno));
    delete result;
    return NULL;
  }

  // We've successfully opened the file!
  return result;
}

void* ContainsFiles(const char* url, const char* hostname,
                    const char* filename2, unsigned int port,
                    const char* options, const char* username,
                    const char* password,
                    VFSDirEntry** items, int* num_items)
{
  return NULL;
}

int GetStartTime(void* ctx)
{
  return 0;
}

int GetTotalTime(void* ctx)
{
  return 0;
}

bool NextChannel(void* context, bool preview)
{
  return false;
}

bool PrevChannel(void* context, bool preview)
{
  return false;
}

bool SelectChannel(void* context, unsigned int uiChannel)
{
  return false;
}

bool UpdateItem(void* context)
{
  return false;
}

}
