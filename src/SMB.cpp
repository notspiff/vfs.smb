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

#include "SMB.h"
#include <xbmc/libXBMC_addon.h>
#include <libsmbclient.h>
#include <iostream>

extern ADDON::CHelper_libXBMC_addon* XBMC;

void xb_smbc_log(const char* msg)
{
  XBMC->Log(ADDON::LOG_INFO, "%s%s", "smb: ", msg);
}

void xb_smbc_auth(const char *srv, const char *shr, char *wg, int wglen,
                  char *un, int unlen, char *pw, int pwlen)
{
  return ;
}

smbc_get_cached_srv_fn orig_cache;

SMBCSRV* xb_smbc_cache(SMBCCTX* c, const char* server, const char* share, const char* workgroup, const char* username)
{
  return orig_cache(c, server, share, workgroup, username);
}

CSMB2& CSMB2::Get()
{
  static CSMB2 instance;

  return instance;
}

CSMB2::CSMB2()
{
  std::cout << "created yo" << std::endl;
  m_IdleTimeout = 0;
  m_context = NULL;
}

CSMB2::~CSMB2()
{
  Deinit();
}

void CSMB2::Deinit()
{
  PLATFORM::CLockObject lock(*this);

  /* samba goes loco if deinited while it has some files opened */
  if (m_context)
  {
    try
    {
      smbc_set_context(NULL);
      smbc_free_context(m_context, 1);
    }
    catch(...)
    {
      XBMC->Log(ADDON::LOG_ERROR,"exception on CSMB2::Deinit. errno: %d", errno);
    }
    m_context = NULL;
  }
}

void CSMB2::Init()
{
  PLATFORM::CLockObject lock(*this);
  if (!m_context)
  {
    // Create ~/.smb/smb.conf. This file is used by libsmbclient.
    // http://us1.samba.org/samba/docs/man/manpages-3/libsmbclient.7.html
    // http://us1.samba.org/samba/docs/man/manpages-3/smb.conf.5.html
    char smb_conf[MAX_PATH];
    snprintf(smb_conf, sizeof(smb_conf), "%s/.smb", getenv("HOME"));
    if (mkdir(smb_conf, 0755) == 0)
    {
      snprintf(smb_conf, sizeof(smb_conf), "%s/.smb/smb.conf", getenv("HOME"));
      FILE* f = fopen(smb_conf, "w");
      if (f != NULL)
      {
        fprintf(f, "[global]\n");

        // make sure we're not acting like a server
        fprintf(f, "\tpreferred master = no\n");
        fprintf(f, "\tlocal master = no\n");
        fprintf(f, "\tdomain master = no\n");

        // use the weaker LANMAN password hash in order to be compatible with older servers
        fprintf(f, "\tclient lanman auth = yes\n");
        fprintf(f, "\tlanman auth = yes\n");

        fprintf(f, "\tsocket options = TCP_NODELAY IPTOS_LOWDELAY SO_RCVBUF=65536 SO_SNDBUF=65536\n");      
        fprintf(f, "\tlock directory = %s/.smb/\n", getenv("HOME"));

        // set wins server if there's one. name resolve order defaults to 'lmhosts host wins bcast'.
        // if no WINS server has been specified the wins method will be ignored.
  /*      if (CSettings::Get().GetString("smb.winsserver").length() > 0 && !StringUtils::EqualsNoCase(CSettings::Get().GetString("smb.winsserver"), "0.0.0.0") )
        {
          fprintf(f, "\twins server = %s\n", CSettings::Get().GetString("smb.winsserver").c_str());
          fprintf(f, "\tname resolve order = bcast wins host\n");
        }
        else*/
          fprintf(f, "\tname resolve order = bcast host\n");

        // use user-configured charset. if no charset is specified,
        // samba tries to use charset 850 but falls back to ASCII in case it is not available
/*        if (g_advancedSettings.m_sambadoscodepage.length() > 0)
          fprintf(f, "\tdos charset = %s\n", g_advancedSettings.m_sambadoscodepage.c_str());
*/
        // if no workgroup string is specified, samba will use the default value 'WORKGROUP'
/*        if ( CSettings::Get().GetString("smb.workgroup").length() > 0 )
          fprintf(f, "\tworkgroup = %s\n", CSettings::Get().GetString("smb.workgroup").c_str());*/
        fclose(f);
      }
    }

    // reads smb.conf so this MUST be after we create smb.conf
    // multiple smbc_init calls are ignored by libsmbclient.
    smbc_init(xb_smbc_auth, 0);

    // setup our context
    m_context = smbc_new_context();
#ifdef DEPRECATED_SMBC_INTERFACE
    smbc_setDebug(m_context, 0);//(g_advancedSettings.m_extraLogLevels & LOGSAMBA)?10:0);
    smbc_setFunctionAuthData(m_context, xb_smbc_auth);
    orig_cache = smbc_getFunctionGetCachedServer(m_context);
    smbc_setFunctionGetCachedServer(m_context, xb_smbc_cache);
    smbc_setOptionOneSharePerServer(m_context, false);
    smbc_setOptionBrowseMaxLmbCount(m_context, 0);
//    smbc_setTimeout(m_context, g_advancedSettings.m_sambaclienttimeout * 1000);
    smbc_setTimeout(m_context, 30 * 1000);
    smbc_setUser(m_context, strdup("guest"));
#else
    m_context->debug = 0;//(g_advancedSettings.m_extraLogLevels & LOGSAMBA?10:0);
    m_context->callbacks.auth_fn = xb_smbc_auth;
    orig_cache = m_context->callbacks.get_cached_srv_fn;
    m_context->callbacks.get_cached_srv_fn = xb_smbc_cache;
    m_context->options.one_share_per_server = false;
    m_context->options.browse_max_lmb_count = 0;
    //m_context->timeout = g_advancedSettings.m_sambaclienttimeout * 1000;
    m_context->timeout = 30 * 1000;
    m_context->user = strdup("guest");
#endif

    // initialize samba and do some hacking into the settings
    if (smbc_init_context(m_context))
    {
      /* setup old interface to use this context */
      smbc_set_context(m_context);
    }
    else
    {
      smbc_free_context(m_context, 1);
      m_context = NULL;
    }
  }
  m_IdleTimeout = 180;
}

void CSMB2::Purge()
{
}

/*
 * For each new connection samba creates a new session
 * But this is not what we want, we just want to have one session at the time
 * This means that we have to call smbc_purge() if samba created a new session
 * Samba will create a new session when:
 * - connecting to another server
 * - connecting to another share on the same server (share, not a different folder!)
 *
 * We try to avoid lot's of purge commands because it slow samba down.
 */
void CSMB2::PurgeEx(const std::string& hostname, const std::string& filename)
{
  PLATFORM::CLockObject lock(*this);
  std::string strShare = filename.substr(0, filename.find('/'));

  m_strLastShare = strShare;
  m_strLastHost = hostname;
}

static void Tokenize(const std::string& str, std::vector<std::string>& tokens,
                     const std::string& delimiters = " ")
{
  // Skip delimiters at beginning.
  //string::size_type lastPos = str.find_first_not_of(delimiters, 0);
  // Don't skip delimiters at beginning.
  std::string::size_type start_pos = 0;
  // Find first "non-delimiter".
  std::string::size_type delim_pos = 0;

  while (std::string::npos != delim_pos)
  {
    delim_pos = str.find_first_of(delimiters, start_pos);
    // Found a token, add it to the vector.
    tokens.push_back(str.substr(start_pos, delim_pos - start_pos));
    start_pos = delim_pos + 1;

    // Find next "non-delimiter"
  }
}



std::string CSMB2::URLEncode(const std::string& domain, 
                            const std::string& hostname, const std::string& filename,
                            const std::string& username, const std::string& password)
{
  /* due to smb wanting encoded urls we have to build it manually */

  std::string flat = "smb://";

  if(!domain.empty())
  {
    char* encoded = XBMC->URLEncode(domain.c_str());
    flat += encoded;
    XBMC->FreeString(encoded);
    flat += ";";
  }

  /* samba messes up of password is set but no username is set. don't know why yet */
  /* probably the url parser that goes crazy */
  if(!username.empty() /* || url.GetPassWord().length() > 0 */)
  {
    char* encoded = XBMC->URLEncode(username.c_str());
    flat += encoded;
    XBMC->FreeString(encoded);
    flat += ":";
    encoded = XBMC->URLEncode(password.c_str());
    flat += encoded;
    XBMC->FreeString(encoded);
    flat += "@";
  }
  char* encoded = XBMC->URLEncode(hostname.c_str());
  flat += encoded;
  XBMC->FreeString(encoded);

  /* okey sadly since a slash is an invalid name we have to tokenize */
  std::vector<std::string> parts;
  std::vector<std::string>::iterator it;
  Tokenize(filename, parts, "/");
  for( it = parts.begin(); it != parts.end(); it++ )
  {
    flat += "/";
    char* encoded = XBMC->URLEncode(it->c_str());
    flat += encoded;
    XBMC->FreeString(encoded);
  }

  /* okey options should go here, thou current samba doesn't support any */

  return flat;
}

/* This is called from CApplication::ProcessSlow() and is used to tell if smbclient have been idle for too long */
void CSMB2::CheckIfIdle()
{
/* We check if there are open connections. This is done without a lock to not halt the mainthread. It should be thread safe as
   worst case scenario is that m_OpenConnections could read 0 and then changed to 1 if this happens it will enter the if wich will lead to another check, wich is locked.  */
  if (m_OpenConnections == 0)
  { /* I've set the the maxiumum IDLE time to be 1 min and 30 sec. */
    PLATFORM::CLockObject lock(*this);
    if (m_OpenConnections == 0 /* check again - when locked */ && m_context != NULL)
    {
      if (m_IdleTimeout > 0)
      {
        m_IdleTimeout--;
      }
      else
      {
        XBMC->Log(ADDON::LOG_INFO, "Samba is idle. Closing the remaining connections");
        Deinit();
      }
    }
  }
}

void CSMB2::SetActivityTime()
{
  /* Since we get called every 500ms from ProcessSlow we limit the tick count to 180 */
  /* That means we have 2 ticks per second which equals 180/2 == 90 seconds */
  m_IdleTimeout = 180;
}

/* The following two function is used to keep track on how many Opened files/directories there are.
   This makes the idle timer not count if a movie is paused for example */
void CSMB2::AddActiveConnection()
{
  PLATFORM::CLockObject lock(*this);
  m_OpenConnections++;
}

void CSMB2::AddIdleConnection()
{
  PLATFORM::CLockObject lock(*this);
  m_OpenConnections--;
  /* If we close a file we reset the idle timer so that we don't have any wierd behaviours if a user
     leaves the movie paused for a long while and then press stop */
  m_IdleTimeout = 180;
}
