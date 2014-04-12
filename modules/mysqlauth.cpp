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
 */

#include <znc/znc.h>
#include <znc/User.h>

#include <mysql/mysql.h>

class CMysqlAuth : public CModule {
public:
	MODCONSTRUCTOR(CMysqlAuth) {
		AddHelpCommand();

		// Database information
		AddCommand("SetConnection", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::SetConnectionCommand), "<db user> <db password> <db host> <db name>");
        AddCommand("SetQuery",      static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::SetQueryCommand), "<sql query>");

		// How to handle user accounts from database
		AddCommand("CreateUser",    static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::CreateUserCommand), "[yes|no]");
		AddCommand("CloneUser",     static_cast<CModCommand::ModCmdFunc>(&CMysqlAuth::CloneUserCommand), "[username]");

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
        if (Reconnect(false)) {
            PutModule("Connection to mysql database successfully");
        } else {
            PutModule("Could not connect to database, did you already set the credentials?");
        }

        return true;
	}

	virtual EModRet OnLoginAttempt(CSmartPtr<CAuthBase> Auth) {
		const CString& sUsername = Auth->GetUsername();
		const CString& sPassword = Auth->GetPassword();
		CUser *pUser(CZNC::Get().FindUser(sUsername));

        // User does not exist and this modules should not create it
		if (!pUser && !CreateUser()) {
			return CONTINUE;
		}

		// Ping database
        if (!Reconnect(true)) {
            return CONTINUE;
        }

        CString sQuery = GetNV("DbQuery");
        if (sQuery.empty()) {
            sQuery = "SELECT 1 FROM znc_user WHERE username = ? AND password = MD5(?);";
        }

		// Prepare statement
        MYSQL_STMT *stmt;
        stmt = mysql_stmt_init(&mysql);
        if (stmt == NULL || mysql_stmt_prepare(stmt, sQuery.c_str(), sizeof(char) * strlen(sQuery.c_str())) != 0) {
            CString err	= mysql_error(&mysql);
            DEBUG("Database statement creation failed: " + err);
		    return CONTINUE;
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
        my_bool is_null[1];
        result.buffer_type     = MYSQL_TYPE_LONG;
        result.buffer          = (void *) &iResults;
        result.is_unsigned     = 0;
        result.is_null         = &is_null[0];
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
		    return CONTINUE;
        }

        // Refuse Login
        if (iResults <= 0) {
            DEBUG("Refuse Login by mysql query");
            return CONTINUE;
        } else {
            DEBUG("Accept Login by mysql query");
        }

        // Accept Login
        if (pUser) {
            Auth->AcceptLogin(*pUser);
            return HALT;
        } else {
            DEBUG("Create User [mysqlauth]: " << sUsername);
            CString sErr;
            pUser = new CUser(sUsername);

            // Clone user
            if (ShouldCloneUser()) {
                CUser *pBaseUser = CZNC::Get().FindUser(CloneUser());

                if (!pBaseUser) {
                    DEBUG("Clone User [" << CloneUser() << "] User not found");
                    delete pUser;
                    pUser = NULL;
                }

                if (pUser && !pUser->Clone(*pBaseUser, sErr)) {
                    DEBUG("Cloning User [" << CloneUser() << "] failed: " << sErr);
                    delete pUser;
                    pUser = NULL;
                }
            }

            // Invalidate password
            if (pUser) {
                // "::" is an invalid MD5 hash, so user won't be able to login by usual method
                pUser->SetPass("::", CUser::HASH_MD5, "::");
                pUser->SetNick(sUsername);
                pUser->SetIdent(sUsername);
            }

            if (pUser && !CZNC::Get().AddUser(pUser, sErr)) {
                DEBUG("Adding user [" << sUsername << "] failed: " << sErr);
                delete pUser;
                pUser = NULL;
            } else {
                Auth->AcceptLogin(*pUser);
                return HALT;
            }
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

	    if (canUseExisting && mysql_ping(&mysql)) {
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

	void SetQueryCommand(const CString &sLine) {
		SetNV("DbQuery", sLine.Token(1, true));

		CString sQuery = GetNV("DbQuery");
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
