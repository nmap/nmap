/**This is the program that's uploaded to a Windows machine when psexec is run. It acts as a Windows
 * service, since that's what Windows expects. When it is started, it's passed a list of programs to
 * run. These programs are all expected to be at the indicated path (whether they were uploaded or
 * they were always present makes no difference).
 *
 * After running the programs, the output from each of them is ciphered with a simple xor encryption
 * (the encryption key is passed as a parameter; because it crosses the wire, it isn't really a
 * security feature, more of validation/obfuscation to prevent sniffers from grabbing the output. This
 * output is placed in a temp file. When the cipher is complete, the output is moved into a new file.
 * When Nmap detects the presence of this new file, it is downloaded, then all files, temp files, and
 * the service (this program) is deleted.
 *
 * One interesting note is that executable files don't require a specific extension to be used by this
 * program. By default, at the time of this writing, Nmap appends a .txt extension to the file.
 *
 * @args argv[1]   The final filename where the ciphered output will go.
 * @args argv[2]   The temporary file where output is sent before being renamed; this is sent as a parameter
 *                 so we can delete it later (if, say, the script fails).
 * @args argv[3]   The number of programs that are going to be run.
 * @args argv[4]   Logging: a boolean value (1 to enable logging, 0 to disable).
 * @args argv[5]   An 'encryption' key for simple 'xor' encryption. This string can be as long or as short
 *                 as you want, but a longer string will be more secure (although this algorithm should
 *                 *never* really be considered secure).
 * @args Remaining There are two arguments for each program to run: a path (including arguments) and
 *                 environmental variables.
 *
 * @auther    Ron Bowes
 * @copyright Ron Bowes
 * @license   "Same as Nmap--See https://nmap.org/book/man-legal.html"
 */

#include <stdio.h>
#include <windows.h>

FILE *outfile;

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

static char *enc_key;
static int   enc_key_loc;

static void log_message(char *format, ...)
{
	static int enabled = 1;

	if(!format)
	{
		enabled = 0;
		DeleteFile("c:\\nmap-log.txt");
	}


	if(enabled)
	{
		va_list argp;
		FILE *file;

		fopen_s(&file, "c:\\nmap-log.txt", "a");

		if(file != NULL)
		{
			va_start(argp, format);
			vfprintf(file, format, argp);
			va_end(argp);
			fprintf(file, "\n");
			fclose(file);
		}
	}
}

static char cipher(char c)
{
	if(strlen(enc_key) == 0)
		return c;

	c = c ^ enc_key[enc_key_loc];
	enc_key_loc = (enc_key_loc + 1) % strlen(enc_key);

	return c;
}

static void output(int num, char *str, int length)
{
	int i;

	if(length == -1)
		length = strlen(str);

	for(i = 0; i < length; i++)
	{
		if(str[i] == '\n')
		{
			fprintf(outfile, "%c", cipher('\n'));
			fprintf(outfile, "%c", cipher('0' + (num % 10)));
		}
		else
		{
			fprintf(outfile, "%c", cipher(str[i]));
		}
	}
}

static void go(int num, char *lpAppPath, char *env, int headless, int include_stderr, char *readfile)
{
	STARTUPINFO         startupInfo;
	PROCESS_INFORMATION processInformation;
	SECURITY_ATTRIBUTES sa;
	HANDLE              stdout_read, stdout_write;
	DWORD               creation_flags;

	int bytes_read;
	char buffer[1024];

	/* Create a security attributes structure. This is required to inherit handles. */
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength              = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;

	if(!headless)
		sa.bInheritHandle       = TRUE;

	/* Create a pipe that'll be used for stdout and stderr. */
	if(!headless)
		CreatePipe(&stdout_read, &stdout_write, &sa, 1);

	/* Initialize the startup info struct. The most important part is setting the stdout/stderr handle to our pipe. */
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	startupInfo.cb         = sizeof(STARTUPINFO);

	if(!headless)
	{
		startupInfo.dwFlags    = STARTF_USESTDHANDLES;
		startupInfo.hStdOutput = stdout_write;
		if(include_stderr)
			startupInfo.hStdError  = stdout_write;
	}

	/* Log a couple messages. */
	log_message("Attempting to load the program: %s", lpAppPath);

	/* Initialize the PROCESS_INFORMATION structure. */
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));

	/* To divide the output from one program to the next */
	output(num, "\n", -1);

	/* Decide on the creation flags */
	creation_flags = CREATE_NO_WINDOW;
	if(headless)
		creation_flags = DETACHED_PROCESS;

	/* Create the actual process with an overly-complicated CreateProcess function. */
	if(!CreateProcess(NULL, lpAppPath, 0, &sa, sa.bInheritHandle, CREATE_NO_WINDOW, env, 0, &startupInfo, &processInformation))
	{
		output(num, "Failed to create the process", -1);

		if(!headless)
		{
			CloseHandle(stdout_write);
			CloseHandle(stdout_read);
		}
	}
	else
	{
		log_message("Successfully created the process!");

		/* Read the pipe, if it isn't headless */
		if(!headless)
		{
			/* Close the write handle -- if we don't do this, the ReadFile() coming up gets stuck. */
			CloseHandle(stdout_write);

			/* Read from the pipe. */
			log_message("Attempting to read from the pipe");
			while(ReadFile(stdout_read, buffer, 1023, &bytes_read, NULL))
			{
				if(strlen(readfile) == 0)
					output(num, buffer, bytes_read);
			}
			CloseHandle(stdout_read);

			/* If we're reading an output file instead of stdout, do it here. */
			if(strlen(readfile) > 0)
			{
				FILE *read;
				errno_t err;

				log_message("Trying to open output file: %s", readfile);
				err = fopen_s(&read, readfile, "rb");

				if(err)
				{
					log_message("Couldn't open the readfile: %d", err);
					output(num, "Couldn't open the output file", -1);
				}
				else
				{
					char buf[1024];
					int count;

					count = fread(buf, 1, 1024, read);
					while(count)
					{
						output(num, buf, count);
						count = fread(buf, 1, 1024, read);
					}

					fclose(read);
				}
			}
		}
		else
		{
			output(num, "Process has been created", -1);
		}

		log_message("Done!");
	}
}

// Control handler function
static void ControlHandler(DWORD request)
{
	switch(request)
	{
		case SERVICE_CONTROL_STOP:

			ServiceStatus.dwWin32ExitCode = 0;
			ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
			SetServiceStatus (hStatus, &ServiceStatus);
			return;

		case SERVICE_CONTROL_SHUTDOWN:

			ServiceStatus.dwWin32ExitCode = 0;
			ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
			SetServiceStatus (hStatus, &ServiceStatus);
			return;

		default:
			break;
	}

	SetServiceStatus(hStatus,  &ServiceStatus);
}



static void die(int err)
{
	// Not enough arguments
	ServiceStatus.dwCurrentState  = SERVICE_STOPPED;
	ServiceStatus.dwWin32ExitCode = err;
	SetServiceStatus(hStatus, &ServiceStatus);
}

static void ServiceMain(int argc, char** argv)
{
	char   *outfile_name;
	char   *tempfile_name;
	int     count;
	int     logging;
	int     result;
	int     i;
	char   *current_directory;

	/* Make sure we got the minimum number of arguments. */
	if(argc < 6)
		return;

	/* Read the arguments. */
	outfile_name      = argv[1];
	tempfile_name     = argv[2];
	count             = atoi(argv[3]);
	logging           = atoi(argv[4]);
	enc_key           = argv[5];
	enc_key_loc       = 0;
	current_directory = argv[6];

	/* If they didn't turn on logging, disable it. */
	if(logging != 1)
		log_message(NULL);

	/* Log the state. */
	log_message("");
	log_message("-----------------------");
	log_message("STARTING");

	/* Log all the arguments. */
	log_message("Arguments: %d\n", argc);
	for(i = 0; i < argc; i++)
		log_message("Argument %d: %s", i, argv[i]);

	/* Set up the service. Likely unnecessary for what we're doing, but it doesn't hurt. */
	ServiceStatus.dwServiceType             = SERVICE_WIN32;
	ServiceStatus.dwCurrentState            = SERVICE_RUNNING;
	ServiceStatus.dwControlsAccepted        = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode           = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint              = 0;
	ServiceStatus.dwWaitHint                = 0;
	hStatus = RegisterServiceCtrlHandler("", (LPHANDLER_FUNCTION)ControlHandler);
	SetServiceStatus(hStatus, &ServiceStatus);

	/* Registering Control Handler failed (this is a bit late, but eh?) */
	if(hStatus == (SERVICE_STATUS_HANDLE)0)
	{
		log_message("Service failed to start");
		die(-1);
		return;
	}

	/* Set the current directory. */
	SetCurrentDirectory(current_directory);

	/* Open the output file. */
	log_message("Opening temporary output file: %s", tempfile_name);

	/* Open the outfile. */
	if(result = fopen_s(&outfile, tempfile_name, "wb"))
	{
		log_message("Couldn't open output file: %d", result);
		die(-1);
	}
	else
	{
		/* Run the programs we were given. */
		for(i = 0; i < count; i++)
		{
			char *program        = argv[(i*5) + 7];
			char *env            = argv[(i*5) + 8];
			char *headless       = argv[(i*5) + 9];
			char *include_stderr = argv[(i*5) + 10];
			char *read_file      = argv[(i*5) + 11];

			go(i, program, env, !strcmp(headless, "true"), !strcmp(include_stderr, "true"), read_file);
		}

		/* Close the output file. */
		if(fclose(outfile))
			log_message("Couldn't close the file: %d", errno);

		/* Rename the output file (this is what tells Nmap we're done. */
		log_message("Renaming file %s => %s", tempfile_name, outfile_name);

		/* I noticed that sometimes, programs inherit the handle to the file (or something), so I can't change it right
		 * away. For this reason, allow about 10 seconds to move it. */
		for(i = 0; i < 10; i++)
		{
			if(rename(tempfile_name, outfile_name))
			{
				log_message("Couldn't rename file: %d (will try %d more times)", errno, 10 - i - 1);
			}
			else
			{
				log_message("File successfully renamed!");
				break;
			}

			Sleep(1000);
		}

		/* Clean up and stop the service. */
		die(0);
	}
}

int main(int argc, char *argv[])
{
	SERVICE_TABLE_ENTRY ServiceTable[2];
	ServiceTable[0].lpServiceName = "";
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;
	// Start the control dispatcher thread for our service
	StartServiceCtrlDispatcher(ServiceTable);
}

