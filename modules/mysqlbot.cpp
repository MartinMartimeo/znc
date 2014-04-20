/*
 * Copyright (C) 2004-2014 ZNC, see the NOTICE file for details.
 * Copyright (C) 2014 Martin Martimeo <martin@martimeo.de>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @class CMysqlBot
 * @author Martin Martimeo <martin@martimeo.de>
 * @brief IRC Bot using a mysql database
 * @description <<<doc
 * 	This module provides some fun actions reading data from a mysql database:
 *
 *  irc_actions:
 *  action_ident | action_text_normal | action_text_me | action_text_anybody | action_text_nobody
 *  ?ident       | <empty arg>        | <bot nick>     | <nick in channel>   | <arg, not corresponding to a nick in chan>
 *
 *  irc_phrases:
 *  phrase_text
 *
 *  Additional it provides a possibility to maintain access level in a chanserv rules channel (of course he needs to have access):
 *  irc_access:
 *  channel_name | irc_auth | irc_access
 *  #chan        | *auth    | access_level
 *
 * doc>>>
 */

#include <znc/znc.h>
#include <znc/Chan.h>
#include <znc/User.h>

#include <mysql/mysql.h>

#include <algorithm>

class CMysqlBot : public CModule {
public:
	MODCONSTRUCTOR(CMysqlBot) {
		AddHelpCommand();

		// Database information
		AddCommand("SetConnection",  static_cast<CModCommand::ModCmdFunc>(&CMysqlBot::SetConnectionCommand),  "<db user> <db password> <db host> <db name>");
        AddCommand("SetActionQuery", static_cast<CModCommand::ModCmdFunc>(&CMysqlBot::SetActionQueryCommand), "<sql query for irc_actions>");
        AddCommand("SetPhraseQuery", static_cast<CModCommand::ModCmdFunc>(&CMysqlBot::SetPhraseQueryCommand), "<sql query for irc_phrases>");
        AddCommand("SetAccessQuery", static_cast<CModCommand::ModCmdFunc>(&CMysqlBot::SetAccessQueryCommand), "<sql query for irc_access>");

		// Init mysql lib
		mysql_library_init(0, NULL, NULL);
	}

	virtual ~CMysqlBot() {
        mysql_close(&mysql);
        mysql_library_end();
	}

	void OnModCommand(const CString& sCommand) {
		if (m_pUser->IsAdmin()) {
			HandleCommand(sCommand);
		} else {
			PutModule("Access denied");
		}
	}

	virtual bool OnLoad(const CString& sArgs, CString& sMessage) {

        // Connect to database
        if (Reconnect(false)) {
            PutModule("Connection to mysql database successfully");
        } else {
            PutModule("Could not connect to database, did you already set the credentials?");
        }

	    CString sMayUse = GetNV("sMayUse");
        if (!m_pUser->IsAdmin() && !sMayUse.ToBool()) {
            sMessage = "You must be admin to use this module";
            return false;
        } else {
            SetNV("sMayUse", "yes");
        }

        return true;
	}

	virtual EModRet OnChanMsg(CNick& Nick, CChan& Channel, CString& sMessage) {
	    CString sArg = sMessage.Token(0);

        if (!sArg.StartsWith("?")) {
            return CONTINUE;
        } else {
            sArg.LeftChomp();
        }

		// Test database
		if (!Reconnect(true)) {
            DEBUG("Connection to database failed");
            return CONTINUE;
        }

        CString sQuery;
        CString sBotNick = m_pUser->GetNick();
        CString sNick = Nick.GetNick();
        CString sIssuerNick = Nick.GetNick();

        // Return a Phrase
        if (sArg.Equals("phrase")) {

            // Get Query
            sQuery = GetNV("DbPhraseQuery");
            if (sQuery.empty()) {
                sQuery = "SELECT phrase_text FROM irc_phrases ORDER BY rand() LIMIT 1";
            }

        // Fun actions
        } else {

            // All other fun actions
            sQuery = GetNV("DbActionQuery");
            if (sQuery.empty()) {
                sQuery = "SELECT %column% FROM irc_actions WHERE action_ident = ?";
            }

            CString sTarget = sMessage.Token(1);

            // Consider which column to load
            if (sTarget.empty()) {
                sQuery.Replace("%column%", "action_text_normal");
            } else if (sTarget.Equals(sBotNick)) {
                sQuery.Replace("%column%", "action_text_me");
                sNick = sBotNick;
            } else if (Channel.FindNick(sTarget)) {
                sQuery.Replace("%column%", "action_text_anybody");
                sNick = sTarget;
            } else {
                sQuery.Replace("%column%", "action_text_nobody");
            }
        }

        // Prepare statement
        MYSQL_STMT *stmt;
        stmt = mysql_stmt_init(&mysql);
        if (stmt == NULL || mysql_stmt_prepare(stmt, sQuery.c_str(), sizeof(char) * strlen(sQuery.c_str())) != 0) {
            CString err	= mysql_error(&mysql);
            DEBUG("Database statement creation failed: " + err);
            return CONTINUE;
        }

        // prepare bind oarameter ident
        if (!sArg.Equals("phrase")) {
            MYSQL_BIND param;
            memset(&param, 0, sizeof(param));
            unsigned long uArg        = sArg.size();
            param.buffer_type         = MYSQL_TYPE_STRING;
            param.buffer              = (const_cast<char*>(sArg.c_str()));
            param.buffer_length       = uArg;
            param.is_null             = 0;
            param.is_unsigned         = true;
            param.length              = &uArg;
            mysql_stmt_bind_param(stmt, &param);
        }

        // Prepare result parameter
        MYSQL_BIND result;
        memset(&result, 0, sizeof(result));
        my_bool is_null;
        char* aBuffer = (char*) malloc(512);
        long unsigned int iBufferSize;
        CString sData;
        result.buffer_type     = MYSQL_TYPE_STRING;
        result.buffer          = (char *) aBuffer;
        result.buffer_length   = 512;
        result.is_unsigned     = 0;
        result.is_null         = &is_null;
        result.length          = &iBufferSize;
        mysql_stmt_bind_result(stmt, &result);

        // Execute
        if (mysql_stmt_execute(stmt) == 0)
        {
            if (mysql_stmt_fetch(stmt) == 0) {
                sData = CString((char *) aBuffer, iBufferSize);
            } else {
                sData = "";
            }
        } else {
            CString err	= mysql_error(&mysql);
            DEBUG("Database statement execution failed: " + err);
            return CONTINUE;
        }

        // Do some translations
        if (!sData.empty()) {
            sData.Replace("%nick", sNick);
            sData.Replace("%anick", sIssuerNick);
            sData.Replace("%me", sBotNick);
            sData.Replace("%chan", Channel.GetName());

            // [?:..] transformation
            CString::size_type iStartPos = sData.find_first_of("[?:");
            while (iStartPos != sData.npos && iStartPos > 0) {
                CString::size_type iEndPos = sData.find_first_of("]", iStartPos);
                CString sRandomize = sData.substr(iStartPos + 3, iEndPos - iStartPos - 3);

                CString::size_type p = (CString::size_type) (count(sRandomize.begin(), sRandomize.end(), '|') * (rand() / (RAND_MAX + 1.0)));

                CString sRandom = sRandomize.Token(p, false, "|");

                sData.erase(iStartPos, iEndPos - iStartPos + 1);
                sData.insert(iStartPos, sRandom);

                iStartPos = sData.find_first_of("[?:");
            }

            PutIRC("PRIVMSG " + Channel.GetName() + " :\001ACTION " + sData + "\001");
        } else {
            DEBUG("Data is empty");
        }

        // Cleanup
        free(aBuffer);
        mysql_stmt_free_result(stmt);

        // Finish
        return CONTINUE;
	}

	void SetConnectionCommand(const CString &sLine) {
	    CString sDbUser = sLine.Token(1);
	    CString sDbPassword = sLine.Token(2);
	    CString sDbHost = sLine.Token(3);
	    CString sDbName = sLine.Token(4);

        SetNV("DbUser",     sDbUser);
        SetNV("DbPassword", sDbPassword);
        SetNV("DbHost",     sDbHost);
        SetNV("DbName",     sDbName);

        if (Reconnect(false)) {
            PutModule("Reconnection successfully");
        } else {
            PutModule("Could not connect to database");
        }
	}

	bool Reconnect(const bool canUseExisting) {

	    if (canUseExisting && !mysql_ping(&mysql)) {
	        DEBUG("Use existing database connection");
	        return true;
	    }

        //mysql_close(&mysql);
	    mysql_init(&mysql);

	    CString sDbUser = GetNV("DbUser");
        CString sDbPassword = GetNV("DbPassword");
        CString sDbHost = GetNV("DbHost");
        CString sDbName = GetNV("DbName");

        if(!mysql_real_connect(&mysql, sDbHost.c_str(), sDbUser.c_str(), sDbPassword.c_str(), sDbName.c_str(), 0, NULL, 0))
        {
            CString err	= mysql_error(&mysql);
            DEBUG("Database login failed: " + err);
            mysql_close(&mysql);
            return false;
        }

        my_bool recon = true;
        mysql_options(&mysql, MYSQL_OPT_RECONNECT, &recon);

	    return true;
	}

	void SetActionQueryCommand(const CString &sLine) {
		SetNV("DbActionQuery", sLine.Token(1, true));

		CString sQuery = GetNV("DbActionQuery");
		PutModule("Using [" + sQuery + "] as query statement");
	}

	void SetPhraseQueryCommand(const CString &sLine) {
		SetNV("DbPhraseQuery", sLine.Token(1, true));

		CString sQuery = GetNV("DbPhraseQuery");
		PutModule("Using [" + sQuery + "] as query statement");
	}

	void SetAccessQueryCommand(const CString &sLine) {
		SetNV("DbAccessQuery", sLine.Token(1, true));

		CString sQuery = GetNV("DbAccessQuery");
		PutModule("Using [" + sQuery + "] as query statement");
	}

private:
	MYSQL mysql;
};

template<> void TModInfo<CMysqlBot>(CModInfo& Info) {
	Info.SetWikiPage("mysqlbot");
	Info.SetHasArgs(false);
}

NETWORKMODULEDEFS(CMysqlBot, "Raises a bot using a mysql table for his actions")
