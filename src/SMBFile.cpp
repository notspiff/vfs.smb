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
#include <libsmbclient.h>

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
  std::string result = CSMB2::Get().URLEncode(url->domain, url->hostname, url->filename, url->username, url->password);
  if (res)
  {
    XBMC->FreeString((char*)url->username);
    XBMC->FreeString((char*)url->password);
  }
  return result;
}

static bool IsValidFile(const std::string& strFileName)
{
  if (strFileName.find('/') == std::string::npos || /* doesn't have sharename */
      strFileName.substr(strFileName.size()-2) == "/." || /* not current folder */
      strFileName.substr(strFileName.size()-3) == "/..")  /* not parent folder */
    return false;
  return true;
}

void* Open(VFSURL* url)
{
  CSMB2::Get().Init();
  CSMB2::Get().AddActiveConnection();
  if (!IsValidFile(url->filename))
  {
    XBMC->Log(ADDON::LOG_INFO, "FileSmb->Open: Bad URL : '%s'",url->redacted);
    return NULL;
  }
  int fd = -1;
  std::string filename = GetAuthenticatedPath(url);
  PLATFORM::CLockObject lock(CSMB2::Get());
  fd = smbc_open(filename.c_str(), O_RDONLY, 0);
  if (fd == -1)
  {
    XBMC->Log(ADDON::LOG_INFO, "FileSmb->Open: Unable to open file : '%s'\nunix_err:'%x' error : '%s'", url->redacted, errno, strerror(errno));
    return NULL;
  }
  XBMC->Log(ADDON::LOG_DEBUG,"CSMB2File::Open - opened %s, fd=%d", url->filename, fd);
  struct stat tmpBuffer;
  if (smbc_stat(filename.c_str(), &tmpBuffer) < 0)
  {
    smbc_close(fd);
    return NULL;
  }
  int64_t ret = smbc_lseek(fd, 0, SEEK_SET);
  if (ret < 0)
  {
    smbc_close(fd);
    return NULL;
  }
  SMBContext* result = new SMBContext;
  result->fd = fd;
  result->size = tmpBuffer.st_size;
  return result;
}

bool Close(void* context)
{
  SMBContext* ctx = (SMBContext*)context;
  XBMC->Log(ADDON::LOG_DEBUG,"CSMB2File::Close closing fd %d", ctx->fd);
  PLATFORM::CLockObject lock(CSMB2::Get());
  smbc_close(ctx->fd);
  CSMB2::Get().AddIdleConnection();
}

unsigned int Read(void* context, void* lpBuf, int64_t uiBufSize)
{
  SMBContext* ctx = (SMBContext*)context;
  if (ctx->fd == -1)
    return 0;

  PLATFORM::CLockObject lock(CSMB2::Get()); // Init not called since it has to be "inited" by now
  CSMB2::Get().SetActivityTime();
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
  CSMB2::Get().Init();
  PLATFORM::CLockObject lock(CSMB2::Get());
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

  PLATFORM::CLockObject lock(CSMB2::Get()); // Init not called since it has to be "inited" by now
  CSMB2::Get().SetActivityTime();
  int64_t pos = smbc_lseek(ctx->fd, iFilePosition, iWhence);

  if ( pos < 0 )
  {
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %"PRId64", %d, %s )", __FUNCTION__, pos, errno, strerror(errno));
    return -1;
  }

  return (int64_t)pos;
}

bool Exists(VFSURL* url)
{
  // we can't open files like smb://file.f or smb://server/file.f
  // if a file matches the if below return false, it can't exist on a samba share.
  if (!IsValidFile(url->filename))
    return false;

  CSMB2::Get().Init();
  std::string strFileName = GetAuthenticatedPath(url);

  struct stat info;

  CSMB2& smb = CSMB2::Get();

  PLATFORM::CLockObject lock(smb);
  int iResult = smbc_stat(strFileName.c_str(), &info);

  if (iResult < 0)
    return false;

  return true;
}

int Stat(VFSURL* url, struct __stat64* buffer)
{
  CSMB2::Get().Init();
  std::string strFileName = GetAuthenticatedPath(url);
  PLATFORM::CLockObject lock(CSMB2::Get());

  struct stat tmpBuffer = {0};
  int iResult = smbc_stat(strFileName.c_str(), &tmpBuffer);

  if (buffer)
  {
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
  }

  return iResult;
}

int IoControl(void* context, XFILE::EIoControl request, void* param)
{
  return -1;
}

void ClearOutIdle()
{
  CSMB2::Get().CheckIfIdle();
}

void DisconnectAll()
{
  CSMB2::Get().Deinit();
}

bool DirectoryExists(VFSURL* url)
{
  PLATFORM::CLockObject lock(CSMB2::Get());
  CSMB2::Get().Init();

  if (!XBMC->AuthenticateURL(url))
    return false;

  std::string strFileName = CSMB2::Get().URLEncode(url->domain, url->hostname, url->filename,
                                                  url->username, url->password);

  XBMC->FreeString((char*)url->username);
  XBMC->FreeString((char*)url->password);

  struct stat info;
  if (smbc_stat(strFileName.c_str(), &info) != 0)
    return false;

  return (info.st_mode & S_IFDIR) ? true : false;
}

void* GetDirectory(VFSURL* url, VFSDirEntry** items,
                   int* num_items, VFSCallbacks* callbacks)
{
  CSMB2::Get().AddActiveConnection();

  PLATFORM::CLockObject lock(CSMB2::Get());
  CSMB2::Get().Init();
  lock.Unlock();

  if (!XBMC->AuthenticateURL(url))
    return NULL;

  std::string strFileName = CSMB2::Get().URLEncode(url->domain, url->hostname,
                                                   url->filename,
                                                   url->username, url->password);
  // remove the / or \ at the end. the samba library does not strip them off
  // don't do this for smb:// !!
  std::string s = strFileName;
  int len = s.length();
  if (len > 1 && s.at(len - 2) != '/' &&
      (s.at(len - 1) == '/' || s.at(len - 1) == '\\'))
  {
    s.erase(len - 1, 1);
  }

  XBMC->Log(ADDON::LOG_DEBUG, "%s - Using authentication url %s", __FUNCTION__, url->redacted);
  lock.Lock();
  int fd = smbc_opendir(s.c_str());
  lock.Unlock();

  while (1)//fd < 0) /* only to avoid goto in following code */
  {
    errno = EACCES;
    char cError[1024];
    if (errno = EACCES)
    {
      callbacks->RequireAuthentication(callbacks->ctx, url->url);
      break;
    }
    if (errno == ENODEV || errno == ENOENT)
    {
      char* str770 = XBMC->GetLocalizedString(770);
      sprintf(cError, str770, errno);
      XBMC->FreeString(str770);
    }
    else
      strcpy(cError,strerror(errno));

    char* str257 = XBMC->GetLocalizedString(257);
    callbacks->SetErrorDialog(callbacks->ctx, str257, cError, NULL, NULL);
    XBMC->FreeString(str257);
    break;
  }
  if (fd < 0)
  {
    XBMC->Log(ADDON::LOG_ERROR, "SMBDirectory->GetDirectory: Unable to open directory : '%s'\nunix_err:'%x' error : '%s'", url->redacted, errno, strerror(errno));
    return NULL;
  }
}

void FreeDirectory(void* items)
{
  CSMB2::Get().AddIdleConnection();
}

bool CreateDirectory(VFSURL* url)
{
  bool success = true;
  PLATFORM::CLockObject lock(CSMB2::Get());
  CSMB2::Get().Init();

  if (!XBMC->AuthenticateURL(url))
    return false;

  std::string strFileName = CSMB2::Get().URLEncode(url->domain, url->hostname, url->filename,
                                                  url->username, url->password);

  XBMC->FreeString((char*)url->username);
  XBMC->FreeString((char*)url->password);

  int result = smbc_mkdir(strFileName.c_str(), 0);
  success = (result == 0 || EEXIST == errno);
  if(!success)
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return success;
}

bool RemoveDirectory(VFSURL* url)
{
  PLATFORM::CLockObject lock(CSMB2::Get());
  CSMB2::Get().Init();

  if (!XBMC->AuthenticateURL(url))
    return false;

  std::string strFileName = CSMB2::Get().URLEncode(url->domain, url->hostname, url->filename,
                                                  url->username, url->password);

  XBMC->FreeString((char*)url->username);
  XBMC->FreeString((char*)url->password);

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
  CSMB2::Get().Init();
  PLATFORM::CLockObject lock(CSMB2::Get());
  dwNumberOfBytesWritten = smbc_write(ctx->fd, (void*)lpBuf, uiBufSize);

  return (int)dwNumberOfBytesWritten;
}

bool Delete(VFSURL* url)
{
  CSMB2::Get().Init();
  std::string strFile = GetAuthenticatedPath(url);

  PLATFORM::CLockObject lock(CSMB2::Get());

  int result = smbc_unlink(strFile.c_str());

  if(result != 0)
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return (result == 0);
}

bool Rename(VFSURL* url, VFSURL* url2)
{
  CSMB2::Get().Init();
  std::string strFile = GetAuthenticatedPath(url);
  std::string strFileNew = GetAuthenticatedPath(url2);
  PLATFORM::CLockObject lock(CSMB2::Get());

  int result = smbc_rename(strFile.c_str(), strFileNew.c_str());

  if(result != 0)
    XBMC->Log(ADDON::LOG_ERROR, "%s - Error( %s )", __FUNCTION__, strerror(errno));

  return (result == 0);
}

void* OpenForWrite(VFSURL* url, bool bOverWrite)
{ 
  CSMB2::Get().Init();
  // we can't open files like smb://file.f or smb://server/file.f
  // if a file matches the if below return false, it can't exist on a samba share.
  if (!IsValidFile(url->filename))
    return NULL;

  std::string strFileName = GetAuthenticatedPath(url);
  PLATFORM::CLockObject lock(CSMB2::Get());

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

void* ContainsFiles(VFSURL* url, VFSDirEntry** items, int* num_items)
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

int GetChunkSize(void* context)
{
  return 1;
}

}
