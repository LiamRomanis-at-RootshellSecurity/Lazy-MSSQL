import pymssql
import re
import getopt, sys
import unicodedata

def banner():
	print ('MSSQL CIS Benchmark Scanner')
        print ('Liam Romanis')
        print ('version 0.3a - alpha testing')
        print ('http://www.intelisecure.com')
        print ('.')

def help():
	print ('mssql.py -t <target IP> -u <username> -p <password>')
	print "Target: Single IP Address"
	print "Username: Two Options"
	print "Mixed Authentication: mssql.py -t 192.168.56.101 -u sa -p sa"
	print "Windows Authentication: mssql.py -t 192.168.56.102 -u DOMAIN\dbadmin -p password'"
	sys.exit(2)


def opts(argv):
    target = ""
    file = ''
    uname = ''
    databas = ''
    try:
        opts, args = getopt.getopt(argv,"ht:u:p:d:",["target="])
    except getopt.GetoptError:
        print ('src-port_scanner.py -t <target>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
 	       help()
 	       sys.exit()
        elif opt in ("-t", "--target"):
		target = arg
	elif opt == "-u":
		uname = arg
	elif opt == "-p":
		passwd = arg
	elif opt == "-d":
		databas = arg

    return target, uname, passwd, databas

if __name__ == "__main__":
	banner()
	if len(sys.argv) == 1:
		help()
		sys.exit(2)

	target, uname, passwd, databas = opts(sys.argv[1:])
	conn = pymssql.connect(server=target, user=uname, password=passwd, database=databas)
	cursor = conn.cursor()
	
	Databases = []
	print "[-] Fetching List of Databases"
	cursor.execute("SELECT name FROM MASTER.dbo.sysdatabases;")
	row = cursor.fetchone()
	while row:
		Databases.append(row)
		row = cursor.fetchone()
		
	print Databases

	print "[-] Getting MSSQL Product Version"
	cursor.execute("SELECT SERVERPROPERTY('ProductLevel') as SP_installed,SERVERPROPERTY('ProductVersion') as Version;")
	row = cursor.fetchone()
	print row
	print "[INSTRUCTION] Check version on CVE to identify missing patches, if any\n"

	cursor.execute("SELECT name,CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';")
	row = cursor.fetchone()
	if row[1] or row[2] != 0:
		print "\n\n[Title] Ad Hoc Distributed Queries are supported\n"
		print "[Finding] Ad Hoc Distributed Queries were found to be supported\n"
		print "[Summary] Enabling Ad Hoc Distributed Queries allows users to query data and execute statements on external data sources. This functionality should be disabled.This feature can be used to remotely access and exploit vulnerabilities on remote SQL Server instances and to run unsafe Visual Basic for Application functions.\n"
		print "[Technical Details]\n2.1 Ensure 'Ad Hoc Distributed Queries' Server Configuration Option is set to '0'\n", row
		print "[Recommendation] Run the following T-SQL command:\nEXECUTE sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXECUTE sp_configure 'Ad Hoc Distributed Queries', 0;\nRECONFIGURE;\nGO\nEXECUTE sp_configure 'show advanced options', 0;\nRECONFIGURE;\n"

	cursor.execute("SELECT name,CAST(value as int) as value_configured,CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'clr enabled';")
	row = cursor.fetchone()
	if row[1] or row[2] != 0:
		print "\n\n[Title] CLR Assemblies Enabled"
		print "[Finding] CLR Assemblies were found to be enabled"
		print "[Summary] The clr enabled option specifies whether user assemblies can be run by SQL Server.Enabling use of CLR assemblies widens the attack surface of SQL Server and puts it at risk from both inadvertent and malicious assemblies."
		print "[Technical Details]\n 2.2 Ensure 'CLR Enabled' Server Configuration Option is set to '0'\n", row
		print "[Recommendation]Run the following T-SQL command:\nEXECUTE sp_configure 'clr enabled', 0;\nRECONFIGURE;\n"

	cursor.execute("SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'cross db ownership chaining';")
	row = cursor.fetchone()
	if row[1] or row[2] != 0:
        	print "\n\n[Title] Cross DB Ownership Chaining Enabled"
		print "[Finding] Cross DB Ownership Chaining was found to be enabled"
        	print "[Summary] The cross db ownership chaining option controls cross-database ownership chaining across all databases at the instance (or server) level. When enabled, this option allows a member of the db_owner role in a database to gain access to objects owned by a login in any other database, causing an unnecessary information disclosure. When required, cross-database ownership chaining should only be enabled for the specific databases requiring it instead of at the instance level for all databases by using the ALTER DATABASE <database_name> SET DB_CHAINING ON command. This database option may not be changed on the master , model , or tempdb system databases."
		print "[Technical Details]\n2.3 Ensure 'Cross DB Ownership Chaining' Server Configuration Option is set to '0'\n", row
		print "[Recommendation] Run the following T-SQL command:\nEXECUTE sp_configure 'cross db ownership chaining', 0;\nRECONFIGURE;\nGO\n"


	cursor.execute("SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Database Mail XPs';")
	row = cursor.fetchone()
	if row[1] or row[2] != 0:
        	print "\n\n[Title] Database Mail XPs is Enabled"
		print "[Finding] Database Mail XPs was found to be enabled"
        	print "[Summary] The Database Mail XPs option controls the ability to generate and transmit email messages from SQL Server. Disabling the Database Mail XPs option reduces the SQL Server surface, eliminates a DOS attack vector and channel to exfiltrate data from the database server to a remote host."
		print "[Technical Details]\n2.4 Ensure 'Database Mail XPs' Server Configuration Option is set to '0'\n", row
		print "[Recommendation] Run the following T-SQL command:\nEXECUTE sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXECUTE sp_configure 'Database Mail XPs', 0;\nRECONFIGURE;\nGO\nEXECUTE sp_configure 'show advanced options', 0;\nRECONFIGURE;\n"

	cursor.execute("SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';")
	row = cursor.fetchone()
	if row[1] or row[2] != 0:
		print "\n\n[Title] Ole Automation Procedures are Enabled"
		print "[Finding] Ole Automation Procedures were found to be enabled"
		print "[Summary] The Ole Automation Procedures option controls whether OLE Automation objects can be instantiated within Transact-SQL batches. These are extended stored procedures that allow SQL Server users to execute functions external to SQL Server. Enabling this option will increase the attack surface of SQL Server and allow users to execute functions in the security context of SQL Server."
		print "[Technical Details]\n2.5 Ensure 'Ole Automation Procedures' Server Configuration Option is set to '0'", row
		print "[Recommendation] Run the following T-SQL command:\nEXECUTE sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXECUTE sp_configure 'Ole Automation Procedures', 0;\nRECONFIGURE;\nGO\nEXECUTE sp_configure 'show advanced options', 0;\nRECONFIGURE;\n"

	cursor.execute("SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'remote access';")
	row = cursor.fetchone()
	if row[1] or row[2] != 0:
		print "\n\n[Title] Remote Access from Stored Procedures Enabled"
		print "[Finding] Remote Access from Stored Procedures was found to be Enabled"
		print "[Summary] The remote access option controls the execution of local stored procedures on remote servers or remote stored procedures on local server. Functionality can be abused to launch a Denial-of-Service (DoS) attack on remote servers by off-loading query processing to a target."
		print "[Technical Details]\n2.6 Ensure 'Remote Access' Server Configuration Option is set to '0'\n", row
		print "[Recommendation] Run the following T-SQL command:\nEXECUTE sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXECUTE sp_configure 'remote access', 0;\nRECONFIGURE;\nGO\nEXECUTE\n sp_configure 'show advanced options', 0;\nRECONFIGURE;\nRestart the Database Engine.\n"


	cursor.execute("USE master; SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'remote admin connections' AND SERVERPROPERTY('IsClustered') = 0;") 
	row = cursor.fetchone()
	if row[1] or row[2] != 0:
		print "\n\n[Title] Remote Admin Connection are Enabled"
		print "[Finding] Remote Admin Connection were found to be enabled"
		print "[Summary] The remote admin connections option controls whether a client application on a remote computer can use the Dedicated Administrator Connection (DAC). The Dedicated Administrator Connection (DAC) lets an administrator access a running server to execute diagnostic functions or Transact-SQL statements, or to troubleshoot problems on the server, even when the server is locked or running in an abnormal state and not responding to a SQL Server Database Engine connection. In a cluster scenario, the administrator may not actually be logged on to the same node that is currently hosting the SQL Server instance and thus is considered 'remote'. Therefore, this setting should usually be enabled ( 1 ) for SQL Server failover clusters; otherwise it should be disabled ( 0 ) which is the default."
		print "[Technical Details] 2.7 Ensure 'Remote Admin Connections' Server Configuration Option is set to '0'\n", row
		print "[Recommendation] Run the following T-SQL command on non-clustered installations:\nEXECUTE sp_configure 'remote admin connections', 0;\nRECONFIGURE;\nGO\n"

	cursor.execute("SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'scan for startup procs';")
	row = cursor.fetchone()
	if row[1] or row[2] != 0:
		print "\n\n[Title] Scan for Startup Procs is Enabled"
		print "[Finding] Scan for Startup Procs was found to be enabled"
		print "[Summary] The scan for startup procs option, if enabled, causes SQL Server to scan for and automatically run all stored procedures that are set to execute upon service startup. Enforcing this control reduces the threat of an entity leveraging these facilities for malicious purposes."
		print "[Technical Details] \n2.8 Ensure 'Scan For Startup Procs' Server Configuration Option is set to '0'\n", row
		print "[Recommendation] Run the following T-SQL command:\nEXECUTE sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXECUTE sp_configure 'scan for startup procs', 0;\nRECONFIGURE;\nGO\nEXECUTE sp_configure 'show advanced options', 0;\nRECONFIGURE;\nRestart the Database Engine.\n"

	cursor.execute("SELECT name, is_trustworthy_on  FROM sys.databases WHERE is_trustworthy_on = 1 AND name != 'msdb';")
	row = cursor.fetchone()
	while row:
		print row[1]
		if row[1]:
			print "\n\n[Title] Databases Marked Trustworthy"
			print "[Finding] A Database was found which is marked as Trustworthy"
			print "[Summary] The TRUSTWORTHY database option allows database objects to access objects in other databases under certain circumstances. This may expose databases to malicious CLR assemblies or extended procedures."
			print "[Technical Details]\n 2.9 Ensure 'Trustworthy' Database Property is set to 'Off'\n", row
			print "[Recommendation] Execute the following T-SQL statement against each database (replace <database_name> below) returned by the Audit Procedure:\nALTER DATABASE [<database_name>] SET TRUSTWORTHY OFF;\n"
		row = cursor.fetchone()
	

	cursor.execute("DECLARE @value nvarchar(256); EXECUTE master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib\Tcp\IPAll', N'TcpPort', @value OUTPUT, N'no_output'; SELECT @value AS TCP_Port WHERE @value = '1433';")
	row = cursor.fetchone()
	while row:
		if "1433" or "1434" in row:
			print "\n\n[Title] The MSSQL Server Default Ports"
			print "[Finding] The MSSQL Server was found to be configured with default ports."
			print "[Summary] If installed, a default SQL Server instance will be assigned a default port of TCP:1433 for TCP/IP communication. Administrators can also manually configure named instances to use TCP:1433 for communication. TCP:1433 is a widely known SQL Server port and this port assignment should be changed. In a multi-instance scenario, each instance must be assigned its own dedicated TCP/IP port. Using a non-default port helps protect the database from attacks directed to the default port."
			print "[Technical Details]\n2.11 Ensure SQL Server is configured to use non-standard ports\n", row
			print "[Recommendation] 1. In SQL Server Configuration Manager, in the console pane, expand SQL Server Network Configuration, expand Protocols for <InstanceName> , and then double-click the TCP/IP protocol\n2. In the TCP/IP Properties dialog box, on the IP Addresses tab, several IP addresses appear in the format IP1 , IP2 , up to IPAll . One of these is for the IP address of the loopback adapter, 127.0.0.1 . Additional IP addresses appear for each IP Address on the computer.\n3. Under IPAll , change the TCP Port field from 1433 to a non-standard port or leave the TCP Port field empty and set the TCP Dynamic Ports value to 0 to enable dynamic port assignment and then click OK.\n4. In the console pane, click SQL Server Services.\n5. In the details pane, right-click SQL Server (<InstanceName>) and then click Restart, to stop and restart SQL Server.\n"
		row = cursor.fetchone()


	cursor.execute("DECLARE @getValue INT; EXEC master..xp_instance_regread @rootkey = N'HKEY_LOCAL_MACHINE', @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib', @value_name = N'HideInstance', @value = @getValue OUTPUT; SELECT @getValue;")
	row = cursor.fetchone()
	while row:
		if 0 in row:
			print "\n\n[Title] MSSQL Instance not marked as Hidden"
			print "[Finding] The MSSQL Instance was not marked as Hidden"
			print "[Summary] Non-clustered SQL Server instances within production environments should be designated as hidden to prevent advertisement by the SQL Server Browser service. Designating production SQL Server instances as hidden leads to a more secure installation because they cannot be enumerated. However, clustered instances may break if this option is selected."
			print "[Technical Details]\n2.12 Ensure 'Hide Instance' option is set to 'Yes' for Production SQL Server instances\n", row
			print "[Recommendation] Execute the following T-SQL to remediate:\nEXEC master..xp_instance_regwrite\n@rootkey = N'HKEY_LOCAL_MACHINE',\n@key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',\n@value_name = N'HideInstance',\n@type = N'REG_DWORD',\n@value = 1;\n"
		row = cursor.fetchone()

	cursor.execute("SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01 AND is_disabled = 0;")
	row = cursor.fetchone()
	if row:
		print "\n\n[Title] The SA Account Enabled"
		print "[Finding] The SA account was found to be enabled. "
		print "[Summary] The sa account is a widely known and often widely used SQL Server account with sysadmin privileges. This is the original login created during installation and always has the principal_id=1 and sid=0x01. Enforcing this control reduces the probability of an attacker executing brute force attacks against a well-known principal."
		print "[Technical Details]\n2.13 Ensure the 'sa' Login Account is set to 'Disabled'\n", row
		print "[Recommendation] Execute the following T-SQL query:\nUSE [master]\nGO\nDECLARE @tsql nvarchar(max)\nSET @tsql = 'ALTER LOGIN ' + SUSER_NAME(0x01) + ' DISABLE'\nEXEC (@tsql)\nGO"


	cursor.execute("SELECT name FROM sys.server_principals WHERE sid = 0x01;")
	row = cursor.fetchone()
	if "sa" in row:
		print "\n\n[Title] SA Account Not Renamed"
		print "[Finding] The SA account had not been renamed"
		print "[Summary] The sa account is a widely known and often widely used SQL Server login with sysadmin privileges. The sa login is the original login created during installation and always has principal_id=1 and sid=0x01. It is more difficult to launch password-guessing and brute-force attacks against the sa login if the name is not known."
		print "[Technical Details]\n2.14 Ensure the 'sa' Login Account has been renamed\n", row
		print "[Recommendation] Replace the <different_user> value within the below syntax and execute to rename the sa login.\nALTER LOGIN sa WITH NAME = <different_user>;"


	cursor.execute("SELECT name, CAST(value as int) as value_configured, CAST(value_in_use as int) as value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';")
	row = cursor.fetchone()
	while row:
		if 0 in row:
			print "\n\n[Title] XP_CMDSHELL Enabled"
			print "[Finding] XP_CMDSHELL had not been disabled"
			print "[Summary] The xp_cmdshell option controls whether the xp_cmdshell extended stored procedure can be used by an authenticated SQL Server user to execute operating-system command shell commands and return results as rows within the SQL client."
			print "[Technical Details]\n2.15 Ensure 'xp_cmdshell' Server Configuration Option is set to '0'\n",row
			print "[Recommendation] Run the following T-SQL command:\nEXECUTE sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXECUTE sp_configure 'xp_cmdshell', 0;\nRECONFIGURE;\nGO\nEXECUTE sp_configure 'show advanced options', 0;\nRECONFIGURE;\n"
		row = cursor.fetchone()


	#cursor.execute("SELECT name, containment, containment_desc, is_auto_close_on FROM sys.databases WHERE containment <> 0 and is_auto_close_on = 1;")
	#row = cursor.fetchone()
	#if row:
	#	print "\n\n[Title] Database AUTO_CLOSE Enabled"
	#	print "[Finding] Database AUTO_CLOSE was found to be enabled"
	#	print "[Summary] AUTO_CLOSE determines if a given database is closed or not after a connection terminates. If enabled, subsequent connections to the given database will require the database to be reopened and relevant procedure caches to be rebuilt. Because authentication of users for contained databases occurs within the database not at the server\instance level, the database must be opened every time to authenticate a user. The frequent opening/closing of the database consumes additional server resources and may contribute to a denial of service."
	#	print "[Technical Details]\n2.16 Ensure 'AUTO_CLOSE' is set to 'OFF' on contained databases\n", row
	#	print "[Recommendation] Execute the following T-SQL, replacing <database_name> with each database name found by the Audit Procedure:\nALTER DATABASE <database_name> SET AUTO_CLOSE OFF;\n"
	#	row = cursor.fetchone()


	cursor.execute("SELECT principal_id, name FROM sys.server_principals WHERE name = 'sa';")
	row = cursor.fetchone()
	if row:
		print "\n\n[Title] SA User Exists"
		print "[Finding] A Login existed with the name SA"
		print "[Summary] The sa login (e.g. principal) is a widely known and often widely used SQL Server account. Therefore, there should not be a login called sa even when the original sa login ( principal_id = 1 ) has been renamed. Enforcing this control reduces the probability of an attacker executing brute force attacks against a well-known principal name."
		print "[Technical Details]\n2.17 Ensure no login exists with the name 'sa'\n", row
		print "[Recommendation] Execute the appropriate ALTER or DROP statement below based on the principal_id returned for the login named sa . Replace the <different_name> value within the below syntax and execute to rename the sa login.\nUSE [master]\nGO\n-- If principal_id = 1 or the login owns database objects, rename the sa login\nALTER LOGIN [sa] WITH NAME = <different_name>;\n GO\n-- If the login owns no database objects, then drop it\n-- Do NOT drop the login if it is principal_id = 1\nDROP LOGIN sa\n"


	#cursor.execute("SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') as [login_mode];")
	#row = cursor.fetchone()
	#if 1 not in row:
	#	print "\n\n[Title] Mixed Mode Authentication Enable"
	#	print "[Finding] MSSQL Authentication was not set to Windows Authentication Mode"
	#	print "[Summary] Windows provides a more robust authentication mechanism than SQL Server authentication."
	#	print "[Technical Details]\n3.1 Ensure 'Server Authentication' Property is set to 'Windows Authentication Mode\n", row
	#	print "[Recommendation] Run the following T-SQL in a Query Window:\nUSE [master]\nGO\nEXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE',N'Software\Microsoft\MSSQLServer\MSSQLServer', N'LoginMode', REG_DWORD, 1\nGO\n"
#
#	for db in Databases:
#		dbv = ''.join(db)
#		if dbv not in ['master','tempdb','msdb']:
#			statement = "'Use " + dbv + ", SELECT grantee_principal_id, permission_name, state_desc FROM sys.database_permissions WHERE grantee_principal_id = ('guest') AND permission_name = 'CONNECT';'"
#			cursor.execute(statement)
#			row = cursor.fetchone()
#			connectresult = []
#			while row:
#				if "guest" in row:
#					connectresult.append(db, row)
#				row = cursor.fetchone()
	
#	if len(connectresult) >= 1:
#		print "\n\n[Title] Guest CONNECT Privilege Identified"
#		print "[Finding] Databases were found where the Guest user "
#		print "[Summary] Remove the right of the guest user to connect to SQL Server databases, except for master ,msdb , and tempdb. A login assumes the identity of the guest user when a login has access to SQL Server but does not have access to a database through its own account and the database has a guest user account. Revoking the CONNECT permission for the guest user will ensure that a login is not able to access database information without explicit access to do so."
#		print "[Technical Details]"
#		for x in connectresult:
#			print x
#		print "[Recommendations]"
		



	cursor.execute("""
	Use master

	DECLARE @dbname VARCHAR(50)   
	DECLARE @statement NVARCHAR(max)

	DECLARE db_cursor CURSOR 
	LOCAL FAST_FORWARD
	FOR  
	SELECT name
	FROM MASTER.dbo.sysdatabases
	WHERE name NOT IN ('master','model','msdb','tempdb','distribution')  
	OPEN db_cursor  
	FETCH NEXT FROM db_cursor INTO @dbname  
	WHILE @@FETCH_STATUS = 0  
	BEGIN  

	SELECT @statement = 'Use ' +@dbname+ ';' + ' EXEC sp_change_users_login @Action="Report";'

	exec sp_executesql @statement

	FETCH NEXT FROM db_cursor INTO @dbname  
	END  
	CLOSE db_cursor  
	DEALLOCATE db_cursor 
	""")
	orphanedresult = []
	row = cursor.fetchone()
	while row:
		orphanedresult.append(row)
		row = cursor.fetchone()

	if len(orphanedresult) >= 1:
		print "\n\n[Title]"
		print "[Finding]"
		print "[Summary] A database user for which the corresponding SQL Server login is undefined or is incorrectly defined on a server instance cannot log in to the instance and is referred to as orphaned and should be removed."
		print "[Technical Details]"
		for z in orphanedresult:
			print z
		print "[Recommendations] Orphan users should be removed to avoid potential misuse of those broken users in any way."



	cursor.execute("""
	Use master

	DECLARE @dbname VARCHAR(50)   
	DECLARE @statement NVARCHAR(max)

	DECLARE db_cursor CURSOR 
	LOCAL FAST_FORWARD
	FOR  
	SELECT name
	FROM MASTER.dbo.sysdatabases
	OPEN db_cursor  
	FETCH NEXT FROM db_cursor INTO @dbname  
	WHILE @@FETCH_STATUS = 0  
	BEGIN  

	SELECT @statement = 'Use ' +@dbname+ ';' +  ' SELECT name, type_desc FROM sys.database_principals;'
	exec sp_executesql @statement

	FETCH NEXT FROM db_cursor INTO @dbname
	END
	CLOSE db_cursor
	DEALLOCATE db_cursor
	""")
	sqluserresult = []
	row = cursor.fetchone()
	while row:
		if "SQL_USER" in row:
			sqluserresult.append(row)
		row = cursor.fetchone()

	if len(sqluserresult) >= 1:
		print "\n\n[Title] User accounts with database authentication were detected. "
		print "[Finding]"
		print "[Summary]"
		print "[Technical Details]"
		for y in sqluserresult:
			print row
		print "[Recommendations]"


	cursor.execute("""SELECT * FROM master.sys.server_permissions WHERE (grantee_principal_id = SUSER_SID(N'public') and state_desc LIKE 'GRANT%') AND NOT (state_desc = 'GRANT' and [permission_name] = 'VIEW ANY DATABASE' and class_desc = 'SERVER') AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 2) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 3) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 4) AND NOT (state_desc = 'GRANT' and [permission_name] = 'CONNECT' and class_desc = 'ENDPOINT' and major_id = 5);""")
	publicpermsresult = []
	row = cursor.fetchone()
	while row:
		publicpermsresult.append(row)
		row = cursor.fetchone()

	if len(publicpermsresult) >= 1:
		print "\n\n[Title] Non-Default Permissions Granted to Public Role"
		print "[Finding]"
		print "[Summary]"
		print "[Technical Details]"
		for w in publicpermsresult:
			print w
		print "[Recommendations]"


	cursor.execute("""
	SELECT pr.[name], pe.[permission_name], pe.[state_desc]
	FROM sys.server_principals pr
	JOIN sys.server_permissions pe
	ON pr.principal_id = pe.grantee_principal_id
	WHERE pr.name like 'BUILTIN%';
	""")
	builtinresult = []
	row = cursor.fetchone()
	while row:
		builtinresult.append(row)
		row = cursor.fetchone()
	if len(builtinresult) >= 1:
		print "\n\n[Title] Windows BUILTIN groups are SQL Logins"
		print "[Finding]"
		print "[Summary] Prior to SQL Server 2008, the BUILTIN\Administrators group was added a SQL Server login with sysadmin privileges during installation by default. Best practices promote creating an Active Directory level group containing approved DBA staff accounts and using this controlled AD group as the login with sysadmin privileges. The AD group should be specified during SQL Server installation and the BUILTIN\Administrators group would therefore have no need to be a login."
		print "[Technical Details]"
		for s in builtinresult:
			print row
		print "[Recommendations]"


	cursor.execute("""
	USE [master]
	SELECT pr.[name] AS LocalGroupName, pe.[permission_name], pe.[state_desc]
	FROM sys.server_principals pr
	JOIN sys.server_permissions pe
	ON pr.[principal_id] = pe.[grantee_principal_id]
	WHERE pr.[type_desc] = 'WINDOWS_GROUP'
	AND pr.[name] like CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';
	""")
	localgrpresult = []
	row = cursor.fetchone()
	while row:
		localgrpresult.append(row)
		row = cursor.fetchone()

	if len(localgrpresult) >= 1:
		print "\n\n[Title] Windows local groups are SQL Logins"
		print "[Finding]"
		print "[Summary]"
		print "[Technical Details]"
		for r in localgrpresult:
			print r
		print "[Recommendations] Local Windows groups should not be used as logins for SQL Server instances."

		

	cursor.execute("""
	USE [msdb];
	SELECT sp.name AS proxyname
	FROM dbo.sysproxylogin spl
	JOIN sys.database_principals dp
	ON dp.sid = spl.sid
	JOIN sysproxies sp
	ON sp.proxy_id = spl.proxy_id
	WHERE principal_id = USER_ID('public');
	""")
	publicroleresult = []
	row = cursor.fetchone()
	while row:
		pubroleresult.append(row)
		row = cursor.fetchone()

	if len(publicroleresult) >= 1:
		print "\n\n[Title] The PUBLIC role in the msdb database is granted access to SQL Agent proxies"
		print "[Summary]"
		print "[Technical Details]"
		for t in publicroleresult:
			print t
		print "[Recommendations]"


	cursor.execute("""
	SELECT l.[name], 'sysadmin membership' AS 'Access_Method'
	FROM sys.sql_logins AS l
	WHERE IS_SRVROLEMEMBER('sysadmin',name) = 1
	AND l.is_expiration_checked <> 1
	UNION ALL
	SELECT l.[name], 'CONTROL SERVER' AS 'Access_Method'
	FROM sys.sql_logins AS l
	JOIN sys.server_permissions AS p
	ON l.principal_id = p.grantee_principal_id
	WHERE p.type = 'CL' AND p.state IN ('G', 'W')
	AND l.is_expiration_checked <> 1;
	""")
	sqlproxyresult = []
	row = cursor.fetchone()
	while row:
		sqlproxyresult.append(row)
		row = cursor.fetchone()
	
	if len(sqlproxyresult) >= 1:
		print "\n\n[Title]"
		print "[Finding] CHECK_EXPIRATION' Option was set to 'OFF' for some SQL Authenticated Logins Within the Sysadmin Role"
		print "[Summary]"
		print "[Technical Findings]"
		for r in sqlproxyresult:
			print r
		print "[Recommendations]"


	cursor.execute("""
	SELECT name, is_disabled
	FROM sys.sql_logins
	WHERE is_policy_checked = 0;
	""")
	chkpolicyresult = []
	row = cursor.fetchone()
	while row:
		chkpolicyresult.append(row)
		row = cursor.fetchone()

	if len(chkpolicyresult) >= 1:
		print "\n\n[Title]"
		print "[Finding] CHECK_POLICY' Option is set to 'OFF' for some SQL Authenticated Logins"
		print "[Summary]"
		print "[Technical Details]"
		for u in chkpolicyresult:
			print u
		print "[Recommendations]"

	cursor.execute("""
	DECLARE @NumErrorLogs int;
	EXEC master.sys.xp_instance_regread
	N'HKEY_LOCAL_MACHINE',
	N'Software\Microsoft\MSSQLServer\MSSQLServer',
	N'NumErrorLogs',
	@NumErrorLogs OUTPUT;
	SELECT ISNULL(@NumErrorLogs, -1) AS [NumberOfLogFiles];
	""")
	logfileresult = []
	row = cursor.fetchone()
	while row:
		logfileresult.append(row)
		row = cursor.fetchone()

	if len(logfileresult) >= 1:
		print "Title"
		print "[Finding]"
		print "[Summary]"
		print "[Technical Details]"
		print " A value of '-1' means that unlimited logs files has been configured"
		for v in logfileresult:
			print v
		print "[Recommendations]The 'Maximum number of error log files' should be greater than or equal to 12"


	cursor.execute("""
	SELECT name,
	CAST(value as int) as value_configured,
	CAST(value_in_use as int) as value_in_use
	FROM sys.configurations
	WHERE name = 'default trace enabled';
	""")
	row = cursor.fetchone()
	if "0" in row:
		print "\n\n[Title]"
		print "[Finding]"
		print "[Summary] 'Default Trace Enabled' Server Configuration Option is set to '0' meaning that Trace is disabled"
		print "[Technical Details]"
		print row
		print "[Recommendations]"


	cursor.execute("""
	EXEC xp_loginconfig 'audit level';
	""")
	row = cursor.fetchone()
	if "all" in row:
		print "\n\n[Title]"
		print "[Finding] 'Login Auditing' is set to 'All'"
		print "[Summary] This will create a lot of noise in the Errorlog which may make tracking potential attacks harder"
		print "[Technical Details]"
		print row
		print "[Recommendations]"


	cursor.execute("""
	SELECT
	S.name AS 'Audit Name'
	, CASE S.is_state_enabled
	WHEN 1 THEN 'Y'
	WHEN 0 THEN 'N' END AS 'Audit Enabled'
	, S.type_desc AS 'Write Location'
	, SA.name AS 'Audit Specification Name'
	, CASE SA.is_state_enabled
	WHEN 1 THEN 'Y'
	WHEN 0 THEN 'N' END AS 'Audit Specification Enabled'
	, SAD.audit_action_name
	, SAD.audited_result
	FROM sys.server_audit_specification_details AS SAD
	JOIN sys.server_audit_specifications AS SA
	ON SAD.server_specification_id = SA.server_specification_id
	JOIN sys.server_audits AS S
	ON SA.audit_guid = S.audit_guid
	WHERE SAD.audit_action_id IN ('CNAU', 'LGFL', 'LGSD');
	""")
	auditspecresult = []
	row = cursor.fetchone()
	while row:
		auditspecresult.append(row)
		row = cursor.fetchone()
	
	if len(auditspecresult) >= 1:
		print "\n\n[Title]"
		print "[Finding]"
		print "[Summary]"
		print "[Technical Details]"
		for q in auditspecresult:
			print q
		print "[Recommendations]"


	cursor.execute("""
	SELECT name,
	permission_set_desc
	FROM sys.assemblies
	where is_user_defined = 1;
	""")
	assembliesresult = []
	row = cursor.fetchone()
	while row:
		assembliesresult.append(row)
		row = cursor.fetchone()
	
	if len(assembliesresult) >= 1:
		print "\n\n[Title]"
		print "[Finding]"
		print "[Summary]"
		print "[Technical Details]"
		for p in assembliesresult:
			print p
		print "[Recommendations]"




	cursor.execute("""
	Use master

	DECLARE @dbname VARCHAR(50)   
	DECLARE @statement NVARCHAR(max)

	DECLARE db_cursor CURSOR 
	LOCAL FAST_FORWARD
	FOR  
	SELECT name
	FROM MASTER.dbo.sysdatabases
	OPEN db_cursor  
	FETCH NEXT FROM db_cursor INTO @dbname  
	WHILE @@FETCH_STATUS = 0  
	BEGIN  

	SELECT @statement = 'Use ' +@dbname+ ';' +  ' SELECT db_name() AS Database_Name, name AS Key_Name, algorithm_desc  FROM sys.symmetric_keys WHERE db_id() > 4;'
	exec sp_executesql @statement

	FETCH NEXT FROM db_cursor INTO @dbname
	END
	CLOSE db_cursor
	DEALLOCATE db_cursor
	""")
	aesresult = []
	row = cursor.fetchone()
	while row:
		if "AES" not in row:
			aesresult.apend(row)
		row = cursor.fetchone()
	
	if len(aesresult) >= 1:
			print "\n\n[Title]"
			print "[Finding]Symmetric Key encryption algorithm' was not set to 'AES_128' or higher for this database"
			print "[Summary]"
			print "[Technical Details]"
			for o in aesresult:
				print o
			print "[recommendations]"


	cursor.execute("""
	Use master

	DECLARE @dbname VARCHAR(50)   
	DECLARE @statement NVARCHAR(max)

	DECLARE db_cursor CURSOR 
	LOCAL FAST_FORWARD
	FOR  
	SELECT name
	FROM MASTER.dbo.sysdatabases
	OPEN db_cursor  
	FETCH NEXT FROM db_cursor INTO @dbname  
	WHILE @@FETCH_STATUS = 0  
	BEGIN  

	SELECT @statement = 'Use ' +@dbname+ ';' +  ' SELECT db_name() AS Database_Name, name AS Key_Name FROM sys.asymmetric_keys WHERE key_length < 2048 AND db_id() > 4;'
	exec sp_executesql @statement

	FETCH NEXT FROM db_cursor INTO @dbname
	END
	CLOSE db_cursor
	DEALLOCATE db_cursor
	""")
	asymetricresult = []
	row = cursor.fetchone()
	while row:
		asymetricresult.append(row)
		row = cursor.fetchone()

	if len(asymetricresult) >= 1:
			print "\n\n[Title]"
			print "[Finding] Asymmetric Key Size was not set to 'greater than or equal to 2048' in non-system databases"
			print "[Summary]"
			print "[Technical Details]"
			for n in asymetricresult:
				print n
			print "[Recommendations]"


