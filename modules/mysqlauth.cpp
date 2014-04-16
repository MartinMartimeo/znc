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
 * @class CMysqlAuth
 * @author Martin Martimeo <martin@martimeo.de>
 * @brief MySQL auth with a database
 * @description <<<doc
 * 	This module allows the creation and authentification of user against a mysql database
 * 
 *  There are 2 relevant queries:
 *  (Note that they are formated as prepared mysql queries, use ? for the placeholder values)
 *   AuthQuery: Takes username and password and must return one field returning a number > 0 if the user is allowed to auth with this credentials
 *   CreateQuery: Takes the username and may return an arbitrary number of fields that are set on creating the user
 *  Defaults are:
 *   AuthQuery: SELECT COUNT(*) FROM znc_user WHERE username = ? AND password = MD5(?);
 *   CreateQuery: SELECT * FROM znc_user WHERE 0=1 AND username = ?;
 *  
 * 
 * doc>>>
 */

#include <znc/znc.h>
#include <znc/User.h>

#include <mysql/mysql.h>

class CMysqlAuth : public CModule {
public:
	MODCONSTRUCTOR(CMysqlAuth) {
		AddHelpCommand();

		// Database information
		AddCommand("SetConnection",  static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::SetConnectionCommand),  "<db user> <db password> <db host> <db name>");
        AddCommand("SetAuthQuery",   static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::SetAuthQueryCommand),   "<sql query taking username, password>");
        AddCommand("SetCreateQuery", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::SetCreateQueryCommand), "<sql query taking username>");

		// How to handle user accounts from database
		AddCommand("CreateUser",     static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::CreateUserCommand),     "[yes|no]");
		AddCommand("CloneUser",      static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::CloneUserCommand),      "[username]");

		// Init mysql lib
		mysql_library_init(0, NULL, NULL);
	}

	virtual ~CMysqlAuth() {
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

        return true;
	}
	
	bool TestAuth(const CString& sUsername, const CString& sPassword) {
		
		// Ping database
        if (!Reconnect(true)) {
            return false;
        }

		// Get Query
        CString sQuery = GetNV("DbAuthQuery");
        if (sQuery.empty()) {
            sQuery = "SELECT 1 FROM znc_user WHERE username = ? AND password = MD5(?);";
        }

		// Prepare statement
        MYSQL_STMT *stmt;
        stmt = mysql_stmt_init(&mysql);
        if (stmt == NULL || mysql_stmt_prepare(stmt, sQuery.c_str(), sizeof(char) * strlen(sQuery.c_str())) != 0) {
            CString err	= mysql_error(&mysql);
            DEBUG("Database statement creation failed: " + err);
		    return false;
        }

        // Create parameters (user, password)
        MYSQL_BIND params[2];
        memset(params, 0, sizeof(params));
        int iResults;

        // Prepare parameter user
        unsigned long uUsername   = sUsername.size();
        params[0].buffer_type     = MYSQL_TYPE_STRING;
        params[0].buffer          = (const_cast<char*>(sUsername.c_str()));
        params[0].buffer_length   = uUsername;
        params[0].is_null         = 0;
        params[0].is_unsigned     = true;
        params[0].length          = &uUsername;

        // Prepare parameter password
        unsigned long uPassword   = sPassword.size();
        params[1].buffer_type     = MYSQL_TYPE_STRING;
        params[1].buffer          = (const_cast<char*>(sPassword.c_str()));
        params[1].buffer_length   = uPassword;
        params[1].is_null         = 0;
        params[1].is_unsigned     = true;
        params[1].length          = &uPassword;

        // Prepare result parameter
        MYSQL_BIND result;
        memset(&result, 0, sizeof(result));
        my_bool is_null;
        result.buffer_type     = MYSQL_TYPE_LONG;
        result.buffer          = (void *) &iResults;
        result.is_unsigned     = 0;
        result.is_null         = &is_null;
        result.length          = 0;
        mysql_stmt_bind_result(stmt, &result);

        // Bind
        mysql_stmt_bind_param(stmt, &params[0]);

        // Execute
        if (mysql_stmt_execute(stmt) == 0)
        {
            mysql_stmt_fetch(stmt);
            mysql_stmt_free_result(stmt);
        } else {
            CString err	= mysql_error(&mysql);
            DEBUG("Database statement execution failed: " + err);
		    return false;
        }

        // Refuse Login
        if (iResults <= 0) {
            DEBUG("Refuse Login by mysql query");
            return false;
        } else {
            DEBUG("Accept Login by mysql query");
            return true;
        }
	}
	
	CUser* Create(const CString& sUsername) {
        DEBUG("Create User [mysqlauth]: " << sUsername);
        CString sErr;
        CUser* pUser = new CUser(sUsername);

        // Clone user
        if (ShouldCloneUser()) {
            CUser *pBaseUser = CZNC::Get().FindUser(CloneUser());

            if (!pBaseUser) {
                DEBUG("Clone User [" << CloneUser() << "] User not found");
                delete pUser;
                return NULL;
            }

            if (pUser && !pUser->Clone(*pBaseUser, sErr)) {
                DEBUG("Cloning User [" << CloneUser() << "] failed: " << sErr);
                delete pUser;
                return NULL;
            }
        }
        
        // Invalidate password
        pUser->SetPass("::", CUser::HASH_MD5, "::");

		// Test database
		if (!Reconnect(true)) {
            DEBUG("Connection to database failed");
			delete pUser;
            return NULL;
        }

		// Get Query
        CString sQuery = GetNV("DbCreateQuery");
        if (sQuery.empty()) {
            sQuery = "SELECT * FROM znc_user WHERE 1=0 AND username = ?;";
        }

		// Prepare statement
        MYSQL_STMT *stmt;
        stmt = mysql_stmt_init(&mysql);
        if (stmt == NULL || mysql_stmt_prepare(stmt, sQuery.c_str(), sizeof(char) * strlen(sQuery.c_str())) != 0) {
            CString err	= mysql_error(&mysql);
            DEBUG("Database statement creation failed: " + err);
            delete pUser;
		    return NULL;
        }
        
        // Prepare parameter user
        MYSQL_BIND param;
        memset(&param, 0, sizeof(param));
        unsigned long uUsername   = sUsername.size();
        param.buffer_type         = MYSQL_TYPE_STRING;
        param.buffer              = (const_cast<char*>(sUsername.c_str()));
        param.buffer_length       = uUsername;
        param.is_null             = 0;
        param.is_unsigned         = true;
        param.length              = &uUsername;

        // Bind
        mysql_stmt_bind_param(stmt, &param);

        // Metainformation
        MYSQL_RES *aRes = mysql_stmt_result_metadata(stmt);

        // We want the max length attribute set please
        my_bool bUpdateMaxLength = 1;
        mysql_stmt_attr_set(stmt, STMT_ATTR_UPDATE_MAX_LENGTH, &bUpdateMaxLength);
        
        // Execute
        if (!mysql_stmt_execute(stmt) == 0)
        {
            CString err	= mysql_stmt_error(stmt);
            DEBUG("Database statement execution failed: " << err);
            delete pUser;
		    return NULL;
        }

        // Store
        if (!mysql_stmt_store_result(stmt) == 0) {
            CString err	= mysql_stmt_error(stmt);
            DEBUG("Database statement storing failed: " << err);
            delete pUser;
		    return NULL;
        }

        // Get the field count
        unsigned int field_count = mysql_num_fields(aRes);
        
        // Build up result bind
        MYSQL_BIND aResult[field_count];
        my_bool is_null[field_count];
        long unsigned int iBufferSize[field_count];
        memset(&aResult, 0, sizeof(aResult));

        // And associate buffers
        for (unsigned int i = 0; i < field_count; i++) {
            MYSQL_FIELD* aField = &aRes->fields[i];

            char* aBuffer = (char*) malloc(aField->max_length);
            aResult[i].buffer_type     = MYSQL_TYPE_STRING;
            aResult[i].buffer          = (char *) aBuffer;
            aResult[i].buffer_length   = aField->max_length;

            aResult[i].is_unsigned     = 0;
            aResult[i].is_null         = &is_null[field_count];
            aResult[i].length          = &iBufferSize[i];
        }

        // bind results
        mysql_stmt_bind_result(stmt, aResult);

        // Fetch and set data
        int iFetchCode = mysql_stmt_fetch(stmt);
        if (iFetchCode == 1) {
            CString err	= mysql_stmt_error(stmt);
            DEBUG("Database statement fetching failed: " << err);
            delete pUser;
		    return NULL;
        }

        // Now set data
        if (iFetchCode == 0) {
            for (unsigned int i = 0; i < field_count; i++) {
                MYSQL_FIELD* aField = &aRes->fields[i];
                CString sData = CString((char *) aResult[i].buffer, iBufferSize[i]);

                if (!sData.empty()) {
                    Set(pUser, aField->name, sData);
                }

                free(aResult[i].buffer);
            }
        } else {
            DEBUG("Database statement returned zero results.");
        }
        mysql_stmt_free_result(stmt);
        
		// Add it to znc
        if (!CZNC::Get().AddUser(pUser, sErr)) {
            DEBUG("Adding user [" << sUsername << "] failed: " << sErr);
            delete pUser;
            return NULL;
        } else {
            return pUser;
        }
	}
	


	void Set(CUser* pUser, const CString& sVar, const CString& sValue) {
		if (sVar == "nick") {
			pUser->SetNick(sValue);
			DEBUG("Nick = " + sValue);
		}
		else if (sVar == "altnick") {
			pUser->SetAltNick(sValue);
			DEBUG("AltNick = " + sValue);
		}
		else if (sVar == "ident") {
			pUser->SetIdent(sValue);
			DEBUG("Ident = " + sValue);
		}
		else if (sVar == "realname") {
			pUser->SetRealName(sValue);
			DEBUG("RealName = " + sValue);
		}
		else if (sVar == "bindhost") {
			pUser->SetBindHost(sValue);
			DEBUG("BindHost = " + sValue);
		}
		else if (sVar == "multiclients") {
			bool b = sValue.ToBool();
			pUser->SetMultiClients(b);
			DEBUG("MultiClients = " + CString(b));
		}
		else if (sVar == "denyloadmod") {
			bool b = sValue.ToBool();
			pUser->SetDenyLoadMod(b);
			DEBUG("DenyLoadMod = " + CString(b));
		}
		else if (sVar == "denysetbindhost") {
			bool b = sValue.ToBool();
			pUser->SetDenySetBindHost(b);
			DEBUG("DenySetBindHost = " + CString(b));
		}
		else if (sVar == "defaultchanmodes") {
			pUser->SetDefaultChanModes(sValue);
			DEBUG("DefaultChanModes = " + sValue);
		}
		else if (sVar == "quitmsg") {
			pUser->SetQuitMsg(sValue);
			DEBUG("QuitMsg = " + sValue);
		}
		else if (sVar == "buffercount") {
			unsigned int i = sValue.ToUInt();
			// Admins don't have to honour the buffer limit
			if (pUser->SetBufferCount(i, m_pUser->IsAdmin())) {
				DEBUG("BufferCount = " + sValue);
			}
		}
		else if (sVar == "keepbuffer") { // XXX compatibility crap, added in 0.207
			bool b = !sValue.ToBool();
			pUser->SetAutoClearChanBuffer(b);
			DEBUG("AutoClearChanBuffer = " + CString(b));
		}
		else if (sVar == "autoclearchanbuffer") {
			bool b = sValue.ToBool();
			pUser->SetAutoClearChanBuffer(b);
			DEBUG("AutoClearChanBuffer = " + CString(b));
		}
		else if (sVar == "password") {
			const CString sSalt = CUtils::GetSalt();
			const CString sHash = CUser::SaltedHash(sValue, sSalt);
			pUser->SetPass(sHash, CUser::HASH_DEFAULT, sSalt);
			DEBUG("Password has been changed!");
		}
		else if (sVar == "maxjoins") {
			unsigned int i = sValue.ToUInt();
			pUser->SetMaxJoins(i);
			DEBUG("MaxJoins = " + CString(pUser->MaxJoins()));
		}
		else if (sVar == "maxnetworks") {
			unsigned int i = sValue.ToUInt();
			pUser->SetMaxNetworks(i);
			DEBUG("MaxNetworks = " + sValue);
		}
		else if (sVar == "jointries") {
			unsigned int i = sValue.ToUInt();
			pUser->SetJoinTries(i);
			DEBUG("JoinTries = " + CString(pUser->JoinTries()));
		}
		else if (sVar == "timezone") {
			pUser->SetTimezone(sValue);
			DEBUG("Timezone = " + pUser->GetTimezone());
		}
		else if (sVar == "admin") {
			bool b = sValue.ToBool();
			pUser->SetAdmin(b);
			DEBUG("Admin = " + CString(pUser->IsAdmin()));
		}
		else if (sVar == "prependtimestamp") {
			bool b = sValue.ToBool();
			pUser->SetTimestampPrepend(b);
			DEBUG("PrependTimestamp = " + CString(b));
		}
		else if (sVar == "appendtimestamp") {
			bool b = sValue.ToBool();
			pUser->SetTimestampAppend(b);
			DEBUG("AppendTimestamp = " + CString(b));
		}
		else if (sVar == "timestampformat") {
			pUser->SetTimestampFormat(sValue);
			DEBUG("TimestampFormat = " + sValue);
		}
		else if (sVar == "dccbindhost") {
			pUser->SetDCCBindHost(sValue);
			DEBUG("DCCBindHost = " + sValue);
		}
		else if (sVar == "statusprefix") {
			if (sVar.find_first_of(" \t\n") == CString::npos) {
				pUser->SetStatusPrefix(sValue);
				DEBUG("StatusPrefix = " + sValue);
			}
		}
#ifdef HAVE_ICU
		else if (sVar == "clientencoding") {
			pUser->SetClientEncoding(sValue);
			DEBUG("ClientEncoding = " + sValue);
		}
#endif
	}	

	virtual EModRet OnLoginAttempt(CSmartPtr<CAuthBase> Auth) {
		const CString& sUsername = Auth->GetUsername();
		CUser *pUser(CZNC::Get().FindUser(sUsername));

        // User does not exist and this modules should not create it
		if (!pUser && !CreateUser()) {
			return CONTINUE;
		}

		// Continue if auth credentials not correct
		if (!TestAuth(sUsername, Auth->GetPassword())) {
			return CONTINUE;	
		}

		// Create user
		if (!pUser) {
			pUser = Create(sUsername);	
		}

        // Accept Login
        if (pUser) {
            Auth->AcceptLogin(*pUser);
            return HALT;
        }
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

	void CreateUserCommand(const CString &sLine) {
		CString sCreate = sLine.Token(1);

		if (!sCreate.empty()) {
			SetNV("CreateUser", sCreate);
		}

		if (CreateUser()) {
			PutModule("We will create users on their first login");
		} else {
			PutModule("We will not create users on their first login");
		}
	}

	bool CreateUser() const {
		return GetNV("CreateUser").ToBool();
	}

	void CloneUserCommand(const CString &sLine) {
		CString sUsername = sLine.Token(1);

		if (!sUsername.empty()) {
			SetNV("CloneUser", sUsername);
		}

		if (ShouldCloneUser()) {
			PutModule("We will clone [" + CloneUser() + "]");
		} else {
			PutModule("We will not clone a user");
		}
	}

	CString CloneUser() const {
		return GetNV("CloneUser");
	}

	bool ShouldCloneUser() {
		return !GetNV("CloneUser").empty();
	}

	void SetAuthQueryCommand(const CString &sLine) {
		SetNV("DbAuthQuery", sLine.Token(1, true));

		CString sQuery = GetNV("DbAuthQuery");
		PutModule("Using [" + sQuery + "] as query statement");
	}

	void SetCreateQueryCommand(const CString &sLine) {
		SetNV("DbCreateQuery", sLine.Token(1, true));

		CString sQuery = GetNV("DbCreateQuery");
		PutModule("Using [" + sQuery + "] as query statement");
	}

private:
	MYSQL mysql;
};

template<> void TModInfo<CMysqlAuth>(CModInfo& Info) {
	Info.SetWikiPage("mysqlauth");
	Info.SetHasArgs(false);
}

GLOBALMODULEDEFS(CMysqlAuth, "Allow users to authenticate via information from a mysql database")
