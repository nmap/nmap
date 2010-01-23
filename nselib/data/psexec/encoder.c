/* encoder.c
 * By Ron Bowes
 * Created January 23, 2010
 *
 * This program encodes (or decodes) a .exe file (or any other kind of file)
 * to be uploaded by smb-psexec.nse. This will prevent antivirus on the
 * scanner from picking up the file, but not on the target. That's probably
 * best. 
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int   ch;

	/* Check the argument. */
	if(argc != 1)
	{
		fprintf(stderr, "Usage: %s < infile > outfile\n", argv[0]);
		return 1;
	}

	/* Retrieve + encode each character till we're done. */
	while((ch = getchar()) != EOF)
		printf("%c", ch ^ 0xFF);

	return 0;
}
